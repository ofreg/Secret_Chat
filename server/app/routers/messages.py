import json
import os
import logging
import secrets
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.models import Chat, Device, DeviceOneTimePreKey, Message, MessageDevicePayload, OneTimePreKey, User
from app.db.session import AsyncSessionLocal, SessionLocal
from app.dependencies.auth import get_current_user
from app.routers.auth import ensure_account_instance_id
from app.utils.avatar import build_avatar_props
from app.utils.csrf import configure_templates, require_csrf
from app.utils.jwt import decode_access_token
from app.utils.time import utc_now
from app.utils.websocket_manager import manager


router = APIRouter(dependencies=[Depends(require_csrf)])
templates = configure_templates(Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates")))
USED_PREKEY_RETENTION_DAYS = 7
MESSAGE_UPLOAD_DIR = Path(os.getenv("MESSAGE_UPLOAD_DIR", "client/static/uploads/messages"))
MAX_MESSAGE_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_MESSAGE_UPLOAD_SIZE_BYTES", 50 * 1024 * 1024))
ALLOWED_MESSAGE_ATTACHMENT_EXTENSIONS = {
    ".jpg": "image",
    ".jpeg": "image",
    ".png": "image",
    ".webp": "image",
    ".gif": "image",
    ".mp4": "video",
    ".webm": "video",
    ".mov": "video",
    ".mp3": "audio",
    ".wav": "audio",
    ".ogg": "audio",
    ".m4a": "audio",
}
audit_logger = logging.getLogger("app.audit")


def resolve_socket_device_id(websocket: WebSocket) -> str | None:
    return (websocket.query_params.get("device_id") or "").strip() or None


def has_complete_x3dh_bundle(user: User) -> bool:
    return bool(
        user.identity_key
        and user.identity_signing_key
        and user.signed_prekey
        and user.signed_prekey_signature
        and user.signed_prekey_key_id
    )


def has_complete_device_bundle(device: Device) -> bool:
    return bool(
        device.identity_key
        and device.identity_signing_key
        and device.signed_prekey
        and device.signed_prekey_signature
        and device.signed_prekey_key_id
    )


def get_delivery_status(message: Message) -> str:
    if message.read_at:
        return "read"
    if message.delivered_at:
        return "delivered"
    return "sent"


def serialize_message(message: Message, sender_name: str, *, historical: bool) -> dict:
    attachment_meta = None
    if message.attachment_meta:
        try:
            attachment_meta = json.loads(message.attachment_meta)
        except json.JSONDecodeError:
            attachment_meta = None

    attachment_payload = None
    if message.attachment_kind and message.attachment_url:
        attachment_payload = {
            "kind": message.attachment_kind,
            "url": message.attachment_url,
            "name": message.attachment_name,
            "mime_type": message.attachment_mime_type,
            "size": message.attachment_size,
        }
        if attachment_meta is not None:
            attachment_payload["meta"] = attachment_meta

    return {
        "type": "message",
        "message_id": message.id,
        "sender": sender_name,
        "sender_device_id": message.sender_device_id,
        "content": message.content,
        "historical": historical,
        "delivery_status": get_delivery_status(message),
        "attachment": attachment_payload,
    }


def serialize_message_for_content(message: Message, sender_name: str, *, historical: bool, content: str) -> dict:
    payload = serialize_message(message, sender_name, historical=historical)
    payload["content"] = content
    return payload


def build_message_status_event(message: Message) -> dict:
    return {
        "type": "message_status",
        "message_id": message.id,
        "delivery_status": get_delivery_status(message),
    }


def get_user_by_email_sync(email: str | None) -> User | None:
    if not email:
        return None

    db: Session = SessionLocal()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


def get_chat_for_user_sync(chat_id: int, user_id: int) -> Chat | None:
    db: Session = SessionLocal()
    try:
        chat = db.query(Chat).filter(Chat.id == chat_id).first()
        if not chat or user_id not in [chat.user1_id, chat.user2_id]:
            return None
        return chat
    finally:
        db.close()


async def notify_message_status(db: AsyncSession, messages: list[Message]):
    if not messages:
        return

    for message in messages:
        result = await db.execute(select(Chat).where(Chat.id == message.chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            continue

        await manager.broadcast_chat(message.chat_id, build_message_status_event(message))


async def mark_messages_delivered_for_user(user_id: int, db: AsyncSession) -> list[Message]:
    result = await db.execute(
        select(Message, Chat)
        .join(Chat, Chat.id == Message.chat_id)
        .where(
            Message.sender_id != user_id,
            Message.delivered_at.is_(None),
            or_(Chat.user1_id == user_id, Chat.user2_id == user_id),
        )
    )

    updated_messages = []
    now = utc_now()
    for message, _chat in result.all():
        message.delivered_at = now
        updated_messages.append(message)

    if updated_messages:
        await db.commit()
        for message in updated_messages:
            await db.refresh(message)

    return updated_messages


async def mark_chat_messages_read(chat_id: int, user_id: int, db: AsyncSession) -> list[Message]:
    result = await db.execute(
        select(Message)
        .where(
            Message.chat_id == chat_id,
            Message.sender_id != user_id,
            Message.read_at.is_(None),
        )
        .order_by(Message.created_at)
    )
    messages = result.scalars().all()

    if not messages:
        return []

    now = utc_now()
    for message in messages:
        if message.delivered_at is None:
            message.delivered_at = now
        message.read_at = now

    await db.commit()
    for message in messages:
        await db.refresh(message)

    return messages


def save_message_attachment(upload: UploadFile, *, encrypted: bool = False) -> dict:
    if encrypted:
        content = upload.file.read(MAX_MESSAGE_UPLOAD_SIZE_BYTES + 1)
        if len(content) > MAX_MESSAGE_UPLOAD_SIZE_BYTES:
            raise ValueError("Attachment is too large")

        MESSAGE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"{secrets.token_hex(16)}.bin"
        (MESSAGE_UPLOAD_DIR / filename).write_bytes(content)

        return {
            "kind": "encrypted",
            "url": f"/static/uploads/messages/{filename}",
            "name": "encrypted-media.bin",
            "mime_type": "application/octet-stream",
            "size": len(content),
        }

    extension = Path(upload.filename or "").suffix.lower()
    attachment_kind = ALLOWED_MESSAGE_ATTACHMENT_EXTENSIONS.get(extension)
    if not attachment_kind:
        raise ValueError("Unsupported attachment type")

    content = upload.file.read(MAX_MESSAGE_UPLOAD_SIZE_BYTES + 1)
    if len(content) > MAX_MESSAGE_UPLOAD_SIZE_BYTES:
        raise ValueError("Attachment is too large")

    MESSAGE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(16)}{extension}"
    (MESSAGE_UPLOAD_DIR / filename).write_bytes(content)

    return {
        "kind": attachment_kind,
        "url": f"/static/uploads/messages/{filename}",
        "name": upload.filename or filename,
        "mime_type": upload.content_type or "application/octet-stream",
        "size": len(content),
    }


@router.get("/messages", response_class=HTMLResponse)
def messages_page(request: Request, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()
    try:
        chats = db.query(Chat).filter(
            or_(Chat.user1_id == current_user.id, Chat.user2_id == current_user.id)
        ).all()

        chat_id = request.query_params.get("chat_id")
        other_identity_key = None
        other_identity_signing_key = None
        selected_chat_user = None
        chat_items = []

        if chat_id:
            chat = db.query(Chat).filter(Chat.id == int(chat_id)).first()
            if chat and current_user.id in [chat.user1_id, chat.user2_id]:
                other_user_id = chat.user2_id if chat.user1_id == current_user.id else chat.user1_id
                selected_chat_user = db.query(User).filter(User.id == other_user_id).first()
                if selected_chat_user:
                    other_identity_key = selected_chat_user.identity_key
                    other_identity_signing_key = selected_chat_user.identity_signing_key

        for chat in chats:
            other_user_id = chat.user2_id if chat.user1_id == current_user.id else chat.user1_id
            other_user = db.query(User).filter(User.id == other_user_id).first()
            if not other_user:
                continue

            chat_items.append(
                {
                    "id": chat.id,
                    "username": other_user.username,
                    **build_avatar_props(other_user),
                }
            )
    finally:
        db.close()

    return templates.TemplateResponse(
        request,
        "messages.html",
        {
            "request": request,
            "chats": chat_items,
            "current_user_id": current_user.id,
            "other_identity_key": other_identity_key,
            "other_identity_signing_key": other_identity_signing_key,
            "chat_id": chat_id,
            "selected_chat_user": (
                {
                    "username": selected_chat_user.username,
                    **build_avatar_props(selected_chat_user),
                }
                if selected_chat_user
                else None
            ),
        },
    )


@router.get("/messages/search")
def search_users(query: str, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()
    try:
        users = db.query(User).filter(
            User.username.ilike(f"%{query}%"),
            User.id != current_user.id,
        ).limit(10).all()
    finally:
        db.close()

    return [{"id": user.id, "username": user.username, **build_avatar_props(user)} for user in users]


@router.post("/messages/upload")
async def upload_message_attachment(
    chat_id: int = Form(...),
    encrypted: bool = Form(False),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
):
    db: Session = SessionLocal()
    try:
        chat = db.query(Chat).filter(Chat.id == chat_id).first()
        if not chat or current_user.id not in [chat.user1_id, chat.user2_id]:
            raise HTTPException(status_code=403, detail="Access denied")

        try:
            attachment = save_message_attachment(file, encrypted=encrypted)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        audit_logger.info(
            "message_attachment_uploaded chat_id=%s user_id=%s kind=%s size=%s",
            chat_id,
            current_user.id,
            attachment["kind"],
            attachment["size"],
        )
        return JSONResponse({"status": "ok", "attachment": attachment})
    finally:
        db.close()


@router.post("/messages/start")
async def start_chat_json(username: str = Form(...), current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        other_user = result.scalar_one_or_none()
        if not other_user or other_user.id == current_user.id:
            audit_logger.warning("chat_start_failed requester_id=%s username=%s", current_user.id, username)
            return {"status": "error", "message": "Не знайдено користувача"}

        if not has_complete_x3dh_bundle(other_user):
            audit_logger.warning("chat_start_missing_keys requester_id=%s other_user_id=%s", current_user.id, other_user.id)
            return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

        active_devices = await get_active_devices_for_user(other_user.id, db)

        u1, u2 = sorted([current_user.id, other_user.id])
        result = await db.execute(select(Chat).where(and_(Chat.user1_id == u1, Chat.user2_id == u2)))
        chat = result.scalar_one_or_none()
        is_new_chat = chat is None

        if not chat:
            chat = Chat(user1_id=u1, user2_id=u2)
            db.add(chat)
            await db.commit()
            await db.refresh(chat)
            audit_logger.info("chat_created chat_id=%s user1_id=%s user2_id=%s", chat.id, u1, u2)
        else:
            audit_logger.info(
                "chat_reused chat_id=%s requester_id=%s other_user_id=%s",
                chat.id,
                current_user.id,
                other_user.id,
            )

        return {
            "status": "ok",
            "chat_id": chat.id,
            "identity_key": other_user.identity_key or "",
            "identity_signing_key": other_user.identity_signing_key or "",
            "prekey_bundle": await (
                issue_prekey_bundle(other_user.id, db) if is_new_chat else peek_prekey_bundle(other_user.id, db)
            ),
            "device_bundles": [
                await (issue_device_prekey_bundle(device, db) if is_new_chat else peek_device_prekey_bundle(device, db))
                for device in active_devices
            ],
            "username": other_user.username,
            **build_avatar_props(other_user),
        }


@router.websocket("/ws/user")
async def websocket_user(websocket: WebSocket):
    device_id = resolve_socket_device_id(websocket)
    token = websocket.cookies.get("access_token")
    if not token:
        audit_logger.warning("ws_user_rejected missing_access_token")
        await websocket.close(code=1008)
        return

    payload = decode_access_token(token)
    if not payload:
        audit_logger.warning("ws_user_rejected invalid_access_token")
        await websocket.close(code=1008)
        return

    user = get_user_by_email_sync(payload.get("sub"))
    if not user:
        audit_logger.warning("ws_user_rejected missing_user email=%s", payload.get("sub"))
        await websocket.close(code=1008)
        return
    user_id = user.id

    audit_logger.info("ws_user_connected user_id=%s", user_id)
    await manager.connect_user(user_id, websocket, device_id=device_id)
    async with AsyncSessionLocal() as db:
        updated_messages = await mark_messages_delivered_for_user(user_id, db)
        await notify_message_status(db, updated_messages)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        audit_logger.info("ws_user_disconnected user_id=%s", user_id)
        manager.disconnect_user(user_id, websocket, device_id=device_id)


@router.websocket("/ws/{chat_id}")
async def websocket_chat(websocket: WebSocket, chat_id: int):
    device_id = resolve_socket_device_id(websocket)
    token = websocket.cookies.get("access_token")
    if not token:
        audit_logger.warning("ws_chat_rejected missing_access_token chat_id=%s", chat_id)
        await websocket.close(code=1008)
        return

    payload = decode_access_token(token)
    if not payload:
        audit_logger.warning("ws_chat_rejected invalid_access_token chat_id=%s", chat_id)
        await websocket.close(code=1008)
        return

    user = get_user_by_email_sync(payload.get("sub"))
    if not user:
        audit_logger.warning("ws_chat_rejected missing_user chat_id=%s email=%s", chat_id, payload.get("sub"))
        await websocket.close(code=1008)
        return

    chat = get_chat_for_user_sync(chat_id, user.id)
    if not chat:
        audit_logger.warning("ws_chat_rejected forbidden chat_id=%s user_id=%s", chat_id, user.id)
        await websocket.close(code=1008)
        return

    user_id = user.id
    username = user.username
    other_user_id = chat.user2_id if user.id == chat.user1_id else chat.user1_id

    async with AsyncSessionLocal() as db:
        updated_messages = await mark_chat_messages_read(chat_id, user_id, db)
        await notify_message_status(db, updated_messages)

        device_payload_map = await load_device_payload_map(chat_id, user_id, device_id, db)
        result = await db.execute(select(Message).where(Message.chat_id == chat_id).order_by(Message.created_at))
        messages = result.scalars().all()
        usernames: dict[int, str] = {}
        for msg in messages:
            if msg.sender_id not in usernames:
                usernames[msg.sender_id] = await get_username(msg.sender_id, db)
        historical_events = [
            serialize_message_for_content(
                msg,
                usernames.get(msg.sender_id, "Unknown"),
                historical=True,
                content=device_payload_map.get(msg.id, msg.content),
            )
            for msg in messages
        ]

    audit_logger.info("ws_chat_connected chat_id=%s user_id=%s", chat_id, user_id)
    await manager.connect_chat(chat_id, user_id, websocket, device_id=device_id)

    await websocket.send_text(json.dumps({
        "type": "status",
        "user_id": other_user_id,
        "is_online": manager.is_online(other_user_id),
    }))

    for event in historical_events:
        await websocket.send_text(json.dumps(event))

    await websocket.send_text(json.dumps({"type": "history_complete"}))

    try:
        while True:
            raw_data = await websocket.receive_text()
            attachment = None
            content = raw_data

            try:
                parsed_payload = json.loads(raw_data)
            except json.JSONDecodeError:
                parsed_payload = None

            if isinstance(parsed_payload, dict) and parsed_payload.get("type") == "media_message":
                attachment = parsed_payload.get("attachment") or None
                content = parsed_payload.get("caption") or ""

            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False)

            attachment_meta = None
            if attachment:
                raw_attachment_meta = attachment.get("meta")
                if raw_attachment_meta is not None:
                    attachment_meta = json.dumps(raw_attachment_meta, ensure_ascii=False)

            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Message.id).where(Message.chat_id == chat_id).limit(1))
                is_first_message = result.scalar_one_or_none() is None

                delivered_at = utc_now() if manager.is_online(other_user_id) else None
                read_at = delivered_at if manager.has_chat_user(chat_id, other_user_id) else None
                msg = Message(
                    chat_id=chat_id,
                    sender_id=user_id,
                    sender_device_id=device_id,
                    content=content,
                    attachment_kind=attachment.get("kind") if attachment else None,
                    attachment_url=attachment.get("url") if attachment else None,
                    attachment_name=attachment.get("name") if attachment else None,
                    attachment_mime_type=attachment.get("mime_type") if attachment else None,
                    attachment_size=attachment.get("size") if attachment else None,
                    attachment_meta=attachment_meta,
                    delivered_at=delivered_at,
                    read_at=read_at,
                )
                db.add(msg)
                await db.commit()
                await db.refresh(msg)
                audit_logger.info(
                    "message_saved chat_id=%s message_id=%s sender_id=%s first_message=%s",
                    chat_id,
                    msg.id,
                    user_id,
                    is_first_message,
                )

                if not device_id:
                    legacy_event = serialize_message_for_content(
                        msg,
                        username,
                        historical=False,
                        content=msg.content,
                    )
                    await manager.notify_chat_user(chat_id, user_id, legacy_event)
                    await manager.notify_chat_user(chat_id, other_user_id, legacy_event)
                else:
                    await persist_message_device_payloads(
                        db,
                        message=msg,
                        sender_user_id=user_id,
                        recipient_user_id=other_user_id,
                        sender_device_id=device_id,
                        parsed_payload=parsed_payload,
                    )

                    sender_payloads = await load_device_payload_map(chat_id, user_id, device_id, db)
                    recipient_devices = await get_active_devices_for_user(other_user_id, db)
                    sender_devices = await get_active_devices_for_user(user_id, db)

                    current_device_event = serialize_message_for_content(
                        msg,
                        username,
                        historical=False,
                        content=sender_payloads.get(msg.id, msg.content),
                    )
                    delivered_to_current = await manager.safe_send(websocket, current_device_event)
                    if not delivered_to_current:
                        manager.disconnect_chat(chat_id, websocket, user_id, device_id=device_id)

                    for recipient_device in recipient_devices:
                        recipient_payload_map = await load_device_payload_map(chat_id, other_user_id, recipient_device.device_id, db)
                        await manager.notify_chat_device(
                            chat_id,
                            recipient_device.device_id,
                            serialize_message_for_content(
                                msg,
                                username,
                                historical=False,
                                content=recipient_payload_map.get(msg.id, msg.content),
                            )
                        )

                    for sender_device in sender_devices:
                        if sender_device.device_id == device_id:
                            continue
                        sender_device_payload_map = await load_device_payload_map(chat_id, user_id, sender_device.device_id, db)
                        await manager.notify_chat_device(
                            chat_id,
                            sender_device.device_id,
                            serialize_message_for_content(
                                msg,
                                username,
                                historical=False,
                                content=sender_device_payload_map.get(msg.id, msg.content),
                            )
                        )

                await manager.notify_user(other_user_id, {"type": "new_message", "chat_id": chat_id})
                await notify_message_status(db, [msg])
                audit_logger.info(
                    "new_message_notified chat_id=%s recipient_user_id=%s message_id=%s",
                    chat_id,
                    other_user_id,
                    msg.id,
                )
    except WebSocketDisconnect:
        audit_logger.info("ws_chat_disconnected chat_id=%s user_id=%s", chat_id, user_id)
        manager.disconnect_chat(chat_id, websocket, user_id, device_id=device_id)


async def get_username(user_id: int, db: AsyncSession):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    return user.username if user else "Unknown"


@router.get("/messages/get_keys")
async def get_keys(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or current_user.id not in [chat.user1_id, chat.user2_id]:
            return {"status": "error", "message": "Чат не знайдено або ви не учасник"}

        other_user_id = chat.user2_id if current_user.id == chat.user1_id else chat.user1_id
        result = await db.execute(select(User).where(User.id == other_user_id))
        other_user = result.scalar_one_or_none()
        if not other_user:
            return {"status": "error", "message": "Співрозмовник не знайдений"}

        if not has_complete_x3dh_bundle(other_user):
            return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

        active_devices = await get_active_devices_for_user(other_user.id, db)

        return {
            "status": "ok",
            "identity_key": other_user.identity_key or "",
            "identity_signing_key": other_user.identity_signing_key or "",
            "prekey_bundle": await peek_prekey_bundle(other_user.id, db),
            "device_bundles": [await peek_device_prekey_bundle(device, db) for device in active_devices],
            "username": other_user.username,
            **build_avatar_props(other_user),
        }


@router.get("/users/prekey-bundle")
async def get_prekey_bundle(username: str, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        other_user = result.scalar_one_or_none()
        if not other_user or other_user.id == current_user.id:
            return {"status": "error", "message": "Користувача не знайдено"}

        if not has_complete_x3dh_bundle(other_user):
            return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

        return {
            "status": "ok",
            "username": other_user.username,
            "bundle": await issue_prekey_bundle(other_user.id, db),
        }


@router.get("/users/device-prekey-bundles")
async def get_device_prekey_bundles(username: str, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        other_user = result.scalar_one_or_none()
        if not other_user or other_user.id == current_user.id:
            return {"status": "error", "message": "РљРѕСЂРёСЃС‚СѓРІР°С‡Р° РЅРµ Р·РЅР°Р№РґРµРЅРѕ"}

        active_devices = await get_active_devices_for_user(other_user.id, db)
        if not active_devices:
            return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

        return {
            "status": "ok",
            "username": other_user.username,
            "devices": [await issue_device_prekey_bundle(device, db) for device in active_devices],
        }


@router.get("/messages/device-keys")
async def get_chat_device_keys(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or current_user.id not in [chat.user1_id, chat.user2_id]:
            return {"status": "error", "message": "Р§Р°С‚ РЅРµ Р·РЅР°Р№РґРµРЅРѕ Р°Р±Рѕ РІРё РЅРµ СѓС‡Р°СЃРЅРёРє"}

        other_user_id = chat.user2_id if current_user.id == chat.user1_id else chat.user1_id
        result = await db.execute(select(User).where(User.id == other_user_id))
        other_user = result.scalar_one_or_none()
        if not other_user:
            return {"status": "error", "message": "РЎРїС–РІСЂРѕР·РјРѕРІРЅРёРє РЅРµ Р·РЅР°Р№РґРµРЅРёР№"}

        active_devices = await get_active_devices_for_user(other_user.id, db)
        if not active_devices:
            return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

        return {
            "status": "ok",
            "username": other_user.username,
            "devices": [await peek_device_prekey_bundle(device, db) for device in active_devices],
            **build_avatar_props(other_user),
        }


@router.get("/users/me")
def users_me(request: Request, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            return {"status": "error", "message": "User not found"}

        account_instance_id = ensure_account_instance_id(user, db)
        current_device_id = (request.headers.get("X-Device-ID") or "").strip() or None
        return {
            "status": "ok",
            "username": user.username,
            "id": user.id,
            "email": user.email,
            "account_instance_id": account_instance_id,
            "current_device_id": current_device_id,
        }
    finally:
        db.close()


@router.get("/users/me/device-bundles")
async def users_me_device_bundles(current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        devices = await get_active_devices_for_user(current_user.id, db)
        return {
            "status": "ok",
            "devices": [
                {
                    "device_id": device.device_id,
                    "device_name": device.device_name,
                    "identity_key": device.identity_key or "",
                    "identity_signing_key": device.identity_signing_key or "",
                }
                for device in devices
            ],
        }


async def issue_prekey_bundle(user_id: int, db: AsyncSession):
    await purge_old_used_prekeys(user_id, db)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not has_complete_x3dh_bundle(user):
        return None

    result = await db.execute(
        select(OneTimePreKey)
        .where(OneTimePreKey.user_id == user_id, OneTimePreKey.used_at.is_(None))
        .order_by(OneTimePreKey.id)
        .limit(1)
    )
    one_time_prekey = result.scalar_one_or_none()

    one_time_payload = None
    if one_time_prekey:
        one_time_prekey.used_at = utc_now()
        await db.commit()
        one_time_payload = {
            "key_id": one_time_prekey.key_id,
            "public_key": one_time_prekey.public_key,
        }

    return {
        "identity_key": user.identity_key or "",
        "identity_signing_key": user.identity_signing_key or "",
        "signed_prekey": user.signed_prekey or "",
        "signed_prekey_signature": user.signed_prekey_signature or "",
        "signed_prekey_key_id": user.signed_prekey_key_id,
        "one_time_prekey": one_time_payload,
    }


async def peek_prekey_bundle(user_id: int, db: AsyncSession):
    await purge_old_used_prekeys(user_id, db)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not has_complete_x3dh_bundle(user):
        return None

    result = await db.execute(
        select(OneTimePreKey)
        .where(OneTimePreKey.user_id == user_id, OneTimePreKey.used_at.is_(None))
        .order_by(OneTimePreKey.id)
        .limit(1)
    )
    one_time_prekey = result.scalar_one_or_none()

    return {
        "identity_key": user.identity_key or "",
        "identity_signing_key": user.identity_signing_key or "",
        "signed_prekey": user.signed_prekey or "",
        "signed_prekey_signature": user.signed_prekey_signature or "",
        "signed_prekey_key_id": user.signed_prekey_key_id,
        "one_time_prekey": (
            {"key_id": one_time_prekey.key_id, "public_key": one_time_prekey.public_key}
            if one_time_prekey
            else None
        ),
    }


async def purge_old_used_prekeys(user_id: int, db: AsyncSession):
    cutoff = utc_now() - timedelta(days=USED_PREKEY_RETENTION_DAYS)
    await db.execute(
        OneTimePreKey.__table__.delete().where(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.used_at.is_not(None),
            OneTimePreKey.used_at < cutoff,
        )
    )
    await db.commit()


async def purge_old_used_device_prekeys(device_id: str, db: AsyncSession):
    cutoff = utc_now() - timedelta(days=USED_PREKEY_RETENTION_DAYS)
    await db.execute(
        DeviceOneTimePreKey.__table__.delete().where(
            DeviceOneTimePreKey.device_id == device_id,
            DeviceOneTimePreKey.used_at.is_not(None),
            DeviceOneTimePreKey.used_at < cutoff,
        )
    )
    await db.commit()


async def get_active_devices_for_user(user_id: int, db: AsyncSession) -> list[Device]:
    result = await db.execute(
        select(Device)
        .where(Device.user_id == user_id, Device.revoked_at.is_(None))
        .order_by(Device.created_at.asc(), Device.id.asc())
    )
    return [device for device in result.scalars().all() if has_complete_device_bundle(device)]


def normalize_device_payload_map(payload_value) -> dict[str, str]:
    if isinstance(payload_value, dict):
        normalized = {}
        for device_id, value in payload_value.items():
            if not isinstance(device_id, str):
                continue
            if isinstance(value, str):
                normalized[str(device_id)] = value
            elif isinstance(value, (dict, list)):
                normalized[str(device_id)] = json.dumps(value, ensure_ascii=False)
        return normalized
    return {}


async def persist_message_device_payloads(
    db: AsyncSession,
    *,
    message: Message,
    sender_user_id: int,
    recipient_user_id: int,
    sender_device_id: str | None,
    parsed_payload,
):
    recipient_payloads = {}
    sender_payloads = {}

    if isinstance(parsed_payload, dict):
        recipient_payloads = normalize_device_payload_map(parsed_payload.get("device_payloads"))
        sender_payloads = normalize_device_payload_map(parsed_payload.get("sender_device_payloads"))

    sender_devices = await get_active_devices_for_user(sender_user_id, db)
    recipient_devices = await get_active_devices_for_user(recipient_user_id, db)

    rows = []
    for device in recipient_devices:
        rows.append(
            MessageDevicePayload(
                message_id=message.id,
                user_id=recipient_user_id,
                device_id=device.device_id,
                payload=recipient_payloads.get(device.device_id, message.content),
                payload_role="recipient",
            )
        )

    for device in sender_devices:
        payload_value = sender_payloads.get(device.device_id, message.content)
        if device.device_id == sender_device_id:
            payload_value = sender_payloads.get(device.device_id, message.content)
        rows.append(
            MessageDevicePayload(
                message_id=message.id,
                user_id=sender_user_id,
                device_id=device.device_id,
                payload=payload_value,
                payload_role="sender",
            )
        )

    if rows:
        db.add_all(rows)
        await db.commit()


async def load_device_payload_map(chat_id: int, user_id: int, device_id: str | None, db: AsyncSession) -> dict[int, str]:
    if not device_id:
        return {}

    result = await db.execute(
        select(MessageDevicePayload)
        .join(Message, Message.id == MessageDevicePayload.message_id)
        .where(
            Message.chat_id == chat_id,
            MessageDevicePayload.user_id == user_id,
            MessageDevicePayload.device_id == device_id,
        )
    )
    return {
        row.message_id: row.payload
        for row in result.scalars().all()
    }


async def issue_device_prekey_bundle(device: Device, db: AsyncSession):
    await purge_old_used_device_prekeys(device.device_id, db)

    result = await db.execute(
        select(DeviceOneTimePreKey)
        .where(DeviceOneTimePreKey.device_id == device.device_id, DeviceOneTimePreKey.used_at.is_(None))
        .order_by(DeviceOneTimePreKey.id)
        .limit(1)
    )
    one_time_prekey = result.scalar_one_or_none()

    one_time_payload = None
    if one_time_prekey:
        one_time_prekey.used_at = utc_now()
        await db.commit()
        one_time_payload = {
            "key_id": one_time_prekey.key_id,
            "public_key": one_time_prekey.public_key,
        }

    return build_device_bundle_payload(device, one_time_payload)


async def peek_device_prekey_bundle(device: Device, db: AsyncSession):
    await purge_old_used_device_prekeys(device.device_id, db)

    result = await db.execute(
        select(DeviceOneTimePreKey)
        .where(DeviceOneTimePreKey.device_id == device.device_id, DeviceOneTimePreKey.used_at.is_(None))
        .order_by(DeviceOneTimePreKey.id)
        .limit(1)
    )
    one_time_prekey = result.scalar_one_or_none()
    return build_device_bundle_payload(
        device,
        (
            {"key_id": one_time_prekey.key_id, "public_key": one_time_prekey.public_key}
            if one_time_prekey
            else None
        ),
    )


def build_device_bundle_payload(device: Device, one_time_payload):
    return {
        "device_id": device.device_id,
        "device_name": device.device_name,
        "identity_key": device.identity_key or "",
        "identity_signing_key": device.identity_signing_key or "",
        "signed_prekey": device.signed_prekey or "",
        "signed_prekey_signature": device.signed_prekey_signature or "",
        "signed_prekey_key_id": device.signed_prekey_key_id,
        "one_time_prekey": one_time_payload,
    }
