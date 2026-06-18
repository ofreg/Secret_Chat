import json
import os
import logging
import secrets
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.db.models import Chat, ChatParticipant, DeletedMessage, Device, DeviceOneTimePreKey, Message, MessageDevicePayload, OneTimePreKey, User
from app.db.session import AsyncSessionLocal, SessionLocal
from app.dependencies.auth import get_current_user
from app.routers.auth import ensure_account_instance_id
from app.utils.avatar import build_avatar_props, build_chat_avatar_props
from app.utils.csrf import configure_templates, require_csrf
from app.utils.jwt import decode_access_token
from app.utils.time import utc_now
from app.utils.websocket_manager import manager


router = APIRouter(dependencies=[Depends(require_csrf)])
templates = configure_templates(Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates")))
USED_PREKEY_RETENTION_DAYS = 7
MESSAGE_UPLOAD_DIR = Path(os.getenv("MESSAGE_UPLOAD_DIR", "client/static/uploads/messages"))
MAX_MESSAGE_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_MESSAGE_UPLOAD_SIZE_BYTES", 50 * 1024 * 1024))
GROUP_AVATAR_UPLOAD_DIR = Path(os.getenv("AVATAR_UPLOAD_DIR", "client/static/uploads/avatars"))
MAX_GROUP_AVATAR_SIZE_BYTES = int(os.getenv("MAX_AVATAR_SIZE_BYTES", 2 * 1024 * 1024))
ALLOWED_GROUP_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
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


def build_group_avatar_props(title: str | None) -> dict:
    normalized_title = (title or "Group").strip() or "Group"
    return {
        "avatar_url": None,
        "avatar_initial": normalized_title[:1].upper(),
        "avatar_class": "avatar-gradient-12",
    }


def build_group_payload(chat: Chat, participants: list[ChatParticipant], users_by_id: dict[int, User], current_user_id: int) -> dict:
    title = (chat.title or "Group chat").strip() or "Group chat"
    member_names = [
        users_by_id[participant.user_id].username
        for participant in participants
        if participant.user_id in users_by_id and participant.user_id != current_user_id
    ]
    members = [
        {
            "user_id": participant.user_id,
            "username": users_by_id[participant.user_id].username,
            **build_avatar_props(users_by_id[participant.user_id]),
        }
        for participant in participants
        if participant.user_id in users_by_id
    ]
    return {
        "username": title,
        "is_group": True,
        "group_key_epoch": chat.group_key_epoch,
        "member_names": member_names,
        "members": members,
        "creator_id": chat.creator_id,
        **build_chat_avatar_props(chat),
    }


def get_chat_clear_cutoff(chat: Chat, user_id: int, participant: ChatParticipant | None = None) -> datetime | None:
    if participant is not None:
        return participant.cleared_at
    if chat.is_group:
        return None
    if user_id == chat.user1_id:
        return chat.user1_cleared_at
    if user_id == chat.user2_id:
        return chat.user2_cleared_at
    return None


def is_chat_hidden_for_user(chat: Chat, user_id: int, participant: ChatParticipant | None = None) -> bool:
    if participant is not None:
        return bool(participant.hidden)
    if chat.is_group:
        return True
    if user_id == chat.user1_id:
        return bool(chat.user1_hidden)
    if user_id == chat.user2_id:
        return bool(chat.user2_hidden)
    return True


def set_chat_hidden_for_user(chat: Chat, user_id: int, hidden: bool, participant: ChatParticipant | None = None):
    if participant is not None:
        participant.hidden = hidden
        if chat.is_group:
            return
    if chat.is_group:
        return
    if user_id == chat.user1_id:
        chat.user1_hidden = hidden
    elif user_id == chat.user2_id:
        chat.user2_hidden = hidden


def set_chat_cleared_for_user(chat: Chat, user_id: int, cleared_at: datetime | None, participant: ChatParticipant | None = None):
    if participant is not None:
        participant.cleared_at = cleared_at
        if chat.is_group:
            return
    if chat.is_group:
        return
    if user_id == chat.user1_id:
        chat.user1_cleared_at = cleared_at
    elif user_id == chat.user2_id:
        chat.user2_cleared_at = cleared_at


def is_message_cleared_for_user(message: Message, chat: Chat, user_id: int, participant: ChatParticipant | None = None) -> bool:
    cutoff = get_chat_clear_cutoff(chat, user_id, participant)
    return bool(cutoff and message.created_at and message.created_at <= cutoff)


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
        "reply_to_message_id": message.reply_to_message_id,
        "sender": sender_name,
        "sender_device_id": message.sender_device_id,
        "content": message.content,
        "historical": historical,
        "delivery_status": get_delivery_status(message),
        "attachment": attachment_payload,
        "deleted_for_all": False,
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


def build_message_deleted_event(message_id: int, *, delete_for_all: bool) -> dict:
    return {
        "type": "message_deleted",
        "message_id": message_id,
        "delete_for_all": delete_for_all,
    }


def build_chat_deleted_event(chat_id: int, *, delete_for_all: bool) -> dict:
    return {
        "type": "chat_deleted",
        "chat_id": chat_id,
        "delete_for_all": delete_for_all,
    }


def get_user_by_email_sync(email: str | None) -> User | None:
    if not email:
        return None

    db: Session = SessionLocal()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


def ensure_direct_chat_participants_sync(chat: Chat, db: Session):
    if chat.is_group:
        return

    existing_ids = {
        user_id
        for (user_id,) in db.query(ChatParticipant.user_id).filter(ChatParticipant.chat_id == chat.id).all()
    }
    required_ids = {user_id for user_id in [chat.user1_id, chat.user2_id] if user_id}
    missing_ids = required_ids - existing_ids
    if not missing_ids:
        return

    for user_id in missing_ids:
        db.add(ChatParticipant(chat_id=chat.id, user_id=user_id))
    db.commit()


async def ensure_direct_chat_participants_async(chat: Chat, db: AsyncSession):
    if chat.is_group:
        return

    result = await db.execute(select(ChatParticipant.user_id).where(ChatParticipant.chat_id == chat.id))
    existing_ids = set(result.scalars().all())
    required_ids = {user_id for user_id in [chat.user1_id, chat.user2_id] if user_id}
    missing_ids = required_ids - existing_ids
    if not missing_ids:
        return

    db.add_all([ChatParticipant(chat_id=chat.id, user_id=user_id) for user_id in missing_ids])
    await db.commit()


def get_chat_participants_sync(chat_id: int, db: Session) -> list[ChatParticipant]:
    return db.query(ChatParticipant).filter(ChatParticipant.chat_id == chat_id).all()


async def get_chat_participants_async(chat_id: int, db: AsyncSession) -> list[ChatParticipant]:
    result = await db.execute(select(ChatParticipant).where(ChatParticipant.chat_id == chat_id))
    return result.scalars().all()


def get_chat_participant_sync(chat_id: int, user_id: int, db: Session) -> ChatParticipant | None:
    return (
        db.query(ChatParticipant)
        .filter(ChatParticipant.chat_id == chat_id, ChatParticipant.user_id == user_id)
        .first()
    )


async def get_chat_participant_async(chat_id: int, user_id: int, db: AsyncSession) -> ChatParticipant | None:
    result = await db.execute(
        select(ChatParticipant).where(
            ChatParticipant.chat_id == chat_id,
            ChatParticipant.user_id == user_id,
        )
    )
    return result.scalar_one_or_none()


def get_participant_user_ids(chat: Chat, participants: list[ChatParticipant] | None = None) -> list[int]:
    if participants:
        user_ids = [participant.user_id for participant in participants]
        if user_ids:
            return user_ids
    return [user_id for user_id in [chat.user1_id, chat.user2_id] if user_id]


def get_direct_other_user_id(chat: Chat, user_id: int) -> int | None:
    if chat.user1_id == user_id:
        return chat.user2_id
    if chat.user2_id == user_id:
        return chat.user1_id
    return None


def get_chat_display_item(chat: Chat, current_user_id: int, participants: list[ChatParticipant], users_by_id: dict[int, User]) -> dict | None:
    if chat.is_group:
        return {
            "id": chat.id,
            **build_group_payload(chat, participants, users_by_id, current_user_id),
        }

    other_user_id = get_direct_other_user_id(chat, current_user_id)
    other_user = users_by_id.get(other_user_id) if other_user_id else None
    if not other_user:
        return None

    return {
        "id": chat.id,
        "username": other_user.username,
        "is_group": False,
        **build_avatar_props(other_user),
    }


async def resolve_reply_target_id(chat_id: int, raw_reply_to_message_id, db: AsyncSession) -> int | None:
    if raw_reply_to_message_id in (None, "", 0, "0"):
        return None

    try:
        reply_to_message_id = int(raw_reply_to_message_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid reply target") from None

    result = await db.execute(
        select(Message).where(
            Message.id == reply_to_message_id,
            Message.chat_id == chat_id,
            Message.deleted_for_all_at.is_(None),
        )
    )
    reply_message = result.scalar_one_or_none()
    if not reply_message:
        raise HTTPException(status_code=400, detail="Reply target not found")

    return reply_to_message_id


def get_chat_for_user_sync(chat_id: int, user_id: int) -> Chat | None:
    db: Session = SessionLocal()
    try:
        chat = db.query(Chat).filter(Chat.id == chat_id).first()
        if not chat:
            return None
        ensure_direct_chat_participants_sync(chat, db)
        participant = get_chat_participant_sync(chat.id, user_id, db)
        if not participant and user_id not in [chat.user1_id, chat.user2_id]:
            return None
        return chat
    finally:
        db.close()


def chat_has_visible_messages_sync(db: Session, chat: Chat, user_id: int, participant: ChatParticipant | None = None) -> bool:
    query = db.query(Message.id).filter(Message.chat_id == chat.id)
    cutoff = get_chat_clear_cutoff(chat, user_id, participant)
    if cutoff is not None:
        query = query.filter(Message.created_at > cutoff)
    return query.first() is not None


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


def remove_message_attachment_file(attachment_url: str | None):
    if not attachment_url:
        return

    prefix = "/static/uploads/messages/"
    if not str(attachment_url).startswith(prefix):
        return

    filename = Path(str(attachment_url)[len(prefix):]).name
    if not filename:
        return

    path = MESSAGE_UPLOAD_DIR / filename
    if path.exists():
        path.unlink()


@router.get("/messages", response_class=HTMLResponse)
def messages_page(request: Request, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()
    try:
        all_chats = db.query(Chat).all()
        for chat in all_chats:
            ensure_direct_chat_participants_sync(chat, db)

        participant_rows = (
            db.query(ChatParticipant)
            .filter(ChatParticipant.user_id == current_user.id)
            .all()
        )
        participant_by_chat_id = {row.chat_id: row for row in participant_rows}
        chat_ids = [row.chat_id for row in participant_rows]
        chats = db.query(Chat).filter(Chat.id.in_(chat_ids)).all() if chat_ids else []

        chat_id = request.query_params.get("chat_id")
        other_identity_key = None
        other_identity_signing_key = None
        selected_chat_user = None
        chat_items = []
        users_by_id = {
            user.id: user
            for user in db.query(User).all()
        }

        if chat_id:
            chat = db.query(Chat).filter(Chat.id == int(chat_id)).first()
            if chat and int(chat_id) in participant_by_chat_id:
                selected_participants = get_chat_participants_sync(chat.id, db)
                if chat.is_group:
                    selected_chat_user = build_group_payload(chat, selected_participants, users_by_id, current_user.id)
                else:
                    other_user_id = get_direct_other_user_id(chat, current_user.id)
                    selected_user_model = users_by_id.get(other_user_id) if other_user_id else None
                    if selected_user_model:
                        selected_chat_user = {
                            "username": selected_user_model.username,
                            "is_group": False,
                            **build_avatar_props(selected_user_model),
                        }
                        other_identity_key = selected_user_model.identity_key
                        other_identity_signing_key = selected_user_model.identity_signing_key

        for chat in chats:
            participant = participant_by_chat_id.get(chat.id)
            if not participant:
                continue
            if is_chat_hidden_for_user(chat, current_user.id, participant) and not chat_has_visible_messages_sync(db, chat, current_user.id, participant):
                continue

            chat_participants = get_chat_participants_sync(chat.id, db)
            chat_item = get_chat_display_item(chat, current_user.id, chat_participants, users_by_id)
            if chat_item:
                chat_items.append(chat_item)

        chat_items.sort(key=lambda item: item["id"])
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
            "selected_chat_user": selected_chat_user,
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


def parse_group_usernames(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    try:
        parsed = json.loads(raw_value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item).strip() for item in parsed if str(item).strip()]


def save_group_avatar_file(upload: UploadFile) -> str:
    extension = Path(upload.filename or "").suffix.lower()
    if extension not in ALLOWED_GROUP_AVATAR_EXTENSIONS:
        raise ValueError("Only JPG, PNG, WEBP, and GIF are supported.")

    content = upload.file.read(MAX_GROUP_AVATAR_SIZE_BYTES + 1)
    if len(content) > MAX_GROUP_AVATAR_SIZE_BYTES:
        raise ValueError("Avatar file is too large.")

    GROUP_AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(16)}{extension}"
    (GROUP_AVATAR_UPLOAD_DIR / filename).write_bytes(content)
    return filename


def remove_group_avatar_file(filename: str | None):
    if not filename:
        return

    path = GROUP_AVATAR_UPLOAD_DIR / filename
    if path.exists():
        path.unlink()


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
        if not chat:
            raise HTTPException(status_code=403, detail="Access denied")
        ensure_direct_chat_participants_sync(chat, db)
        if not get_chat_participant_sync(chat.id, current_user.id, db):
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
            chat = Chat(user1_id=u1, user2_id=u2, is_group=False, creator_id=current_user.id)
            db.add(chat)
            await db.commit()
            await db.refresh(chat)
            db.add_all([
                ChatParticipant(chat_id=chat.id, user_id=u1),
                ChatParticipant(chat_id=chat.id, user_id=u2),
            ])
            await db.commit()
            audit_logger.info("chat_created chat_id=%s user1_id=%s user2_id=%s", chat.id, u1, u2)
        else:
            await ensure_direct_chat_participants_async(chat, db)
            current_participant = await get_chat_participant_async(chat.id, current_user.id, db)
            set_chat_hidden_for_user(chat, current_user.id, False, current_participant)
            await db.commit()
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


@router.post("/messages/start-group")
async def start_group_chat_json(
    title: str = Form(...),
    usernames: str = Form(...),
    current_user: User = Depends(get_current_user),
):
    normalized_title = title.strip()
    if not normalized_title:
        return {"status": "error", "message": "Group title is required."}

    usernames_list = parse_group_usernames(usernames)
    unique_usernames = []
    for username in usernames_list:
        if username not in unique_usernames and username != current_user.username:
            unique_usernames.append(username)

    if len(unique_usernames) < 2:
        return {"status": "error", "message": "Select at least two other users for a group."}

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username.in_(unique_usernames)))
        users = result.scalars().all()
        users_by_username = {user.username: user for user in users}

        if len(users_by_username) != len(unique_usernames):
            return {"status": "error", "message": "Some selected users were not found."}

        for user in users:
            if not has_complete_x3dh_bundle(user):
                return {"status": "error", "message": f"User {user.username} has not initialized X3DH keys yet."}
            active_devices = await get_active_devices_for_user(user.id, db)
            if not active_devices:
                return {"status": "error", "message": f"User {user.username} has no active devices."}

        chat = Chat(
            user1_id=current_user.id,
            user2_id=None,
            is_group=True,
            title=normalized_title,
            creator_id=current_user.id,
            group_key_epoch=1,
        )
        db.add(chat)
        await db.commit()
        await db.refresh(chat)

        participants = [ChatParticipant(chat_id=chat.id, user_id=current_user.id)]
        participants.extend(ChatParticipant(chat_id=chat.id, user_id=user.id) for user in users)
        db.add_all(participants)
        await db.commit()

        for user in users:
            await manager.notify_user(user.id, {"type": "new_chat", "chat_id": chat.id})
        await manager.notify_user(current_user.id, {"type": "new_chat", "chat_id": chat.id})

        flat_device_bundles = []
        participant_payloads = []
        for user in users:
            devices = await get_active_devices_for_user(user.id, db)
            bundles = [await issue_device_prekey_bundle(device, db) for device in devices]
            flat_device_bundles.extend(bundles)
            participant_payloads.append(
                {
                    "user_id": user.id,
                    "username": user.username,
                    "device_bundles": bundles,
                    **build_avatar_props(user),
                }
            )

        return {
            "status": "ok",
            "chat_id": chat.id,
            "is_group": True,
            "username": normalized_title,
            "group_key_epoch": chat.group_key_epoch,
            "device_bundles": flat_device_bundles,
            "participants": participant_payloads,
            "members": [
                {
                    "user_id": current_user.id,
                    "username": current_user.username,
                    **build_avatar_props(current_user),
                },
                *[
                    {
                        "user_id": user.id,
                        "username": user.username,
                        **build_avatar_props(user),
                    }
                    for user in users
                ],
            ],
            "creator_id": current_user.id,
            **build_chat_avatar_props(chat),
        }


@router.get("/chats/{chat_id}/details")
async def get_chat_details(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            raise HTTPException(status_code=404, detail="Chat not found")

        await ensure_direct_chat_participants_async(chat, db)
        participants = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participants)
        if current_user.id not in participant_user_ids:
            raise HTTPException(status_code=403, detail="Access denied")

        users_result = await db.execute(select(User).where(User.id.in_(participant_user_ids)))
        users = users_result.scalars().all()
        users_by_id = {user.id: user for user in users}

        if chat.is_group:
            return {
                "status": "ok",
                "chat_id": chat.id,
                **build_group_payload(chat, participants, users_by_id, current_user.id),
            }

        other_user_id = get_direct_other_user_id(chat, current_user.id)
        other_user = users_by_id.get(other_user_id) if other_user_id else None
        if not other_user:
            raise HTTPException(status_code=404, detail="Chat peer not found")

        return {
            "status": "ok",
            "chat_id": chat.id,
            "username": other_user.username,
            "is_group": False,
            **build_avatar_props(other_user),
        }


@router.post("/chats/{chat_id}/metadata")
async def update_group_metadata(
    chat_id: int,
    title: str = Form(""),
    avatar: UploadFile | None = File(None),
    current_user: User = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or not chat.is_group:
            raise HTTPException(status_code=404, detail="Group chat not found")

        await ensure_direct_chat_participants_async(chat, db)
        participants = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participants)
        if current_user.id not in participant_user_ids:
            raise HTTPException(status_code=403, detail="Access denied")
        if chat.creator_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the group creator can update metadata")

        normalized_title = title.strip()
        if normalized_title:
            chat.title = normalized_title[:120]

        old_avatar_filename = chat.avatar_filename
        if avatar and avatar.filename:
            try:
                chat.avatar_filename = save_group_avatar_file(avatar)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc

        await db.commit()
        if chat.avatar_filename and chat.avatar_filename != old_avatar_filename:
            remove_group_avatar_file(old_avatar_filename)

        users_result = await db.execute(select(User).where(User.id.in_(participant_user_ids)))
        users = users_result.scalars().all()
        users_by_id = {user.id: user for user in users}
        payload = {
            "type": "chat_meta_updated",
            "chat_id": chat.id,
            **build_group_payload(chat, participants, users_by_id, current_user.id),
        }
        for participant_user_id in participant_user_ids:
            await manager.notify_chat_user(chat.id, participant_user_id, payload)
            await manager.notify_user(participant_user_id, payload)

        return {"status": "ok", **payload}


@router.post("/chats/{chat_id}/participants")
async def add_group_participant(
    chat_id: int,
    username: str = Form(...),
    current_user: User = Depends(get_current_user),
):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or not chat.is_group:
            raise HTTPException(status_code=404, detail="Group chat not found")

        await ensure_direct_chat_participants_async(chat, db)
        participants = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participants)
        if current_user.id not in participant_user_ids:
            raise HTTPException(status_code=403, detail="Access denied")
        if chat.creator_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the group creator can add users")

        result = await db.execute(select(User).where(User.username == username.strip()))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.id in participant_user_ids:
            raise HTTPException(status_code=400, detail="User is already in the group")
        if not has_complete_x3dh_bundle(user):
            raise HTTPException(status_code=400, detail="User has not initialized X3DH keys yet")

        devices = await get_active_devices_for_user(user.id, db)
        if not devices:
            raise HTTPException(status_code=400, detail="User has no active devices")

        db.add(ChatParticipant(chat_id=chat.id, user_id=user.id))
        chat.group_key_epoch = max(1, int(chat.group_key_epoch or 1)) + 1
        await db.commit()

        participants = await get_chat_participants_async(chat.id, db)
        users_result = await db.execute(select(User).where(User.id.in_(get_participant_user_ids(chat, participants))))
        users = users_result.scalars().all()
        users_by_id = {row.id: row for row in users}
        bundles = [await issue_device_prekey_bundle(device, db) for device in devices]
        payload = {
            "type": "chat_participants_updated",
            "chat_id": chat.id,
            "added_user": {
                "user_id": user.id,
                "username": user.username,
                "device_bundles": bundles,
                **build_avatar_props(user),
            },
            **build_group_payload(chat, participants, users_by_id, current_user.id),
        }
        for participant_user_id in get_participant_user_ids(chat, participants):
            await manager.notify_chat_user(chat.id, participant_user_id, payload)
            await manager.notify_user(participant_user_id, payload)

        return {"status": "ok", **payload}


@router.delete("/chats/{chat_id}/participants/{user_id}")
async def remove_group_participant(chat_id: int, user_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or not chat.is_group:
            raise HTTPException(status_code=404, detail="Group chat not found")

        await ensure_direct_chat_participants_async(chat, db)
        participants = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participants)
        if current_user.id not in participant_user_ids:
            raise HTTPException(status_code=403, detail="Access denied")
        if chat.creator_id != current_user.id and current_user.id != user_id:
            raise HTTPException(status_code=403, detail="Only the group creator can remove other users")
        if chat.creator_id == user_id and current_user.id != user_id:
            raise HTTPException(status_code=400, detail="The group creator cannot be removed by another user")

        participant = await get_chat_participant_async(chat.id, user_id, db)
        if not participant:
            raise HTTPException(status_code=404, detail="Participant not found")

        await db.delete(participant)
        chat.group_key_epoch = max(1, int(chat.group_key_epoch or 1)) + 1
        await db.commit()

        if current_user.id == user_id and chat.creator_id == user_id:
            remaining = await get_chat_participants_async(chat.id, db)
            if remaining:
                chat.creator_id = remaining[0].user_id
                await db.commit()

        participants = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participants)
        users_result = await db.execute(select(User).where(User.id.in_(participant_user_ids)))
        users = users_result.scalars().all()
        users_by_id = {row.id: row for row in users}

        payload = {
            "type": "chat_participants_updated",
            "chat_id": chat.id,
            "removed_user_id": user_id,
            **build_group_payload(chat, participants, users_by_id, current_user.id if current_user.id in participant_user_ids else (participant_user_ids[0] if participant_user_ids else user_id)),
        }
        for participant_user_id in participant_user_ids:
            await manager.notify_chat_user(chat.id, participant_user_id, payload)
            await manager.notify_user(participant_user_id, payload)
        removed_user_event = {"type": "chat_deleted", "chat_id": chat.id, "delete_for_all": False}
        await manager.revoke_chat_user(chat.id, user_id, removed_user_event)
        await manager.notify_user(user_id, removed_user_event)

        return {"status": "ok", **payload}


@router.post("/messages/{message_id}/delete-self")
async def delete_message_for_self(message_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Message).where(Message.id == message_id))
        message = result.scalar_one_or_none()
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        result = await db.execute(select(Chat).where(Chat.id == message.chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            raise HTTPException(status_code=403, detail="Access denied")
        await ensure_direct_chat_participants_async(chat, db)
        if not await get_chat_participant_async(chat.id, current_user.id, db):
            raise HTTPException(status_code=403, detail="Access denied")

        result = await db.execute(
            select(DeletedMessage).where(
                DeletedMessage.user_id == current_user.id,
                DeletedMessage.message_id == message_id,
            )
        )
        existing = result.scalar_one_or_none()
        if not existing:
            db.add(DeletedMessage(user_id=current_user.id, message_id=message_id))
            await db.commit()

        event = build_message_deleted_event(message_id, delete_for_all=False)
        await manager.notify_chat_user(chat.id, current_user.id, event)
        audit_logger.info("message_deleted_for_self chat_id=%s message_id=%s user_id=%s", chat.id, message_id, current_user.id)
        return {"status": "ok"}


@router.post("/messages/{message_id}/delete-all")
async def delete_message_for_all(message_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Message).where(Message.id == message_id))
        message = result.scalar_one_or_none()
        if not message:
            raise HTTPException(status_code=404, detail="Message not found")

        result = await db.execute(select(Chat).where(Chat.id == message.chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            raise HTTPException(status_code=403, detail="Access denied")
        await ensure_direct_chat_participants_async(chat, db)
        participant_rows = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participant_rows)
        if current_user.id not in participant_user_ids:
            raise HTTPException(status_code=403, detail="Access denied")
        if message.sender_id != current_user.id:
            raise HTTPException(status_code=403, detail="Only the sender can delete the message for all")

        attachment_url = message.attachment_url
        message.deleted_for_all_at = utc_now()
        message.deleted_for_all_by_user_id = current_user.id
        message.attachment_kind = None
        message.attachment_url = None
        message.attachment_name = None
        message.attachment_mime_type = None
        message.attachment_size = None
        message.attachment_meta = None
        await db.commit()
        remove_message_attachment_file(attachment_url)

        event = build_message_deleted_event(message_id, delete_for_all=True)
        for participant_user_id in participant_user_ids:
            await manager.notify_chat_user(chat.id, participant_user_id, event)
        audit_logger.info("message_deleted_for_all chat_id=%s message_id=%s user_id=%s", chat.id, message_id, current_user.id)
        return {"status": "ok"}


@router.post("/chats/{chat_id}/delete-self")
async def delete_chat_for_self(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            raise HTTPException(status_code=403, detail="Access denied")
        await ensure_direct_chat_participants_async(chat, db)
        current_participant = await get_chat_participant_async(chat.id, current_user.id, db)
        if not current_participant:
            raise HTTPException(status_code=403, detail="Access denied")

        deleted_at = utc_now()
        set_chat_hidden_for_user(chat, current_user.id, True, current_participant)
        set_chat_cleared_for_user(chat, current_user.id, deleted_at, current_participant)
        await db.commit()

        event = build_chat_deleted_event(chat_id, delete_for_all=False)
        await manager.notify_chat_user(chat_id, current_user.id, event)
        await manager.notify_user(current_user.id, event)
        audit_logger.info("chat_deleted_for_self chat_id=%s user_id=%s", chat_id, current_user.id)
        return {"status": "ok"}


@router.post("/chats/{chat_id}/delete-all")
async def delete_chat_for_all(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            raise HTTPException(status_code=403, detail="Access denied")
        await ensure_direct_chat_participants_async(chat, db)
        participant_rows = await get_chat_participants_async(chat.id, db)
        participant_user_ids = get_participant_user_ids(chat, participant_rows)
        if current_user.id not in participant_user_ids:
            raise HTTPException(status_code=403, detail="Access denied")

        deleted_at = utc_now()
        participants_by_user_id = {participant.user_id: participant for participant in participant_rows}
        for participant_user_id in participant_user_ids:
            participant = participants_by_user_id.get(participant_user_id)
            set_chat_hidden_for_user(chat, participant_user_id, True, participant)
            set_chat_cleared_for_user(chat, participant_user_id, deleted_at, participant)
        await db.commit()

        event = build_chat_deleted_event(chat_id, delete_for_all=True)
        for participant_user_id in participant_user_ids:
            await manager.notify_chat_user(chat_id, participant_user_id, event)
            await manager.notify_user(participant_user_id, event)
        audit_logger.info("chat_deleted_for_all chat_id=%s user_id=%s", chat_id, current_user.id)
        return {"status": "ok"}


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

    async with AsyncSessionLocal() as db:
        await ensure_direct_chat_participants_async(chat, db)
        participant_rows = await get_chat_participants_async(chat.id, db)
        participants_by_user_id = {participant.user_id: participant for participant in participant_rows}
        participant_user_ids = get_participant_user_ids(chat, participant_rows)
        other_user_ids = [participant_id for participant_id in participant_user_ids if participant_id != user_id]
        current_participant = participants_by_user_id.get(user_id)

        updated_messages = await mark_chat_messages_read(chat_id, user_id, db)
        await notify_message_status(db, updated_messages)

        device_payload_map = await load_device_payload_map(chat_id, user_id, device_id, db)
        deleted_message_ids = await get_deleted_message_ids(chat_id, user_id, db)
        result = await db.execute(select(Message).where(Message.chat_id == chat_id).order_by(Message.created_at))
        messages = [
            message
            for message in result.scalars().all()
            if is_message_visible_to_user(message, chat, user_id, deleted_message_ids, current_participant)
        ]
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

    if not chat.is_group and other_user_ids:
        await websocket.send_text(json.dumps({
            "type": "status",
            "user_id": other_user_ids[0],
            "is_online": manager.is_online(other_user_ids[0]),
        }))

    for event in historical_events:
        await websocket.send_text(json.dumps(event))

    await websocket.send_text(json.dumps({"type": "history_complete"}))

    try:
        while True:
            raw_data = await websocket.receive_text()
            attachment = None
            content = raw_data
            reply_to_message_id = None
            encrypted_content_payload = None

            try:
                parsed_payload = json.loads(raw_data)
            except json.JSONDecodeError:
                parsed_payload = None

            if isinstance(parsed_payload, dict):
                reply_to_message_id = parsed_payload.get("reply_to_message_id")

            if isinstance(parsed_payload, dict) and parsed_payload.get("type") == "media_message":
                attachment = parsed_payload.get("attachment") or None
                content = parsed_payload.get("caption") or ""
                encrypted_content_payload = parsed_payload.get("caption")
            else:
                encrypted_content_payload = parsed_payload

            if not isinstance(content, str):
                content = json.dumps(content, ensure_ascii=False)

            attachment_meta = None
            if attachment:
                raw_attachment_meta = attachment.get("meta")
                if raw_attachment_meta is not None:
                    attachment_meta = json.dumps(raw_attachment_meta, ensure_ascii=False)

            async with AsyncSessionLocal() as db:
                await ensure_direct_chat_participants_async(chat, db)
                participant_rows = await get_chat_participants_async(chat.id, db)
                participants_by_user_id = {participant.user_id: participant for participant in participant_rows}
                participant_user_ids = get_participant_user_ids(chat, participant_rows)
                if user_id not in participant_user_ids:
                    audit_logger.warning(
                        "ws_chat_message_rejected removed_participant chat_id=%s user_id=%s",
                        chat_id,
                        user_id,
                    )
                    await manager.revoke_chat_user(
                        chat_id,
                        user_id,
                        {"type": "chat_deleted", "chat_id": chat_id, "delete_for_all": False},
                    )
                    return
                other_user_ids = [participant_id for participant_id in participant_user_ids if participant_id != user_id]
                result = await db.execute(select(Message.id).where(Message.chat_id == chat_id).limit(1))
                is_first_message = result.scalar_one_or_none() is None
                reply_to_message_id = await resolve_reply_target_id(chat_id, reply_to_message_id, db)

                delivered_at = utc_now() if any(manager.is_online(other_user_id) for other_user_id in other_user_ids) else None
                read_at = delivered_at if any(manager.has_chat_user(chat_id, other_user_id) for other_user_id in other_user_ids) else None
                msg = Message(
                    chat_id=chat_id,
                    sender_id=user_id,
                    sender_device_id=device_id,
                    reply_to_message_id=reply_to_message_id,
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
                set_chat_hidden_for_user(chat, user_id, False, participants_by_user_id.get(user_id))
                for other_user_id in other_user_ids:
                    set_chat_hidden_for_user(chat, other_user_id, False, participants_by_user_id.get(other_user_id))
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
                    for participant_user_id in participant_user_ids:
                        await manager.notify_chat_user(chat_id, participant_user_id, legacy_event)
                else:
                    await persist_message_device_payloads(
                        db,
                        message=msg,
                        sender_user_id=user_id,
                        recipient_user_ids=other_user_ids,
                        sender_device_id=device_id,
                        parsed_payload=encrypted_content_payload,
                    )

                    sender_payloads = await load_device_payload_map(chat_id, user_id, device_id, db)
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

                    for recipient_user_id in other_user_ids:
                        recipient_devices = await get_active_devices_for_user(recipient_user_id, db)
                        for recipient_device in recipient_devices:
                            recipient_payload_map = await load_device_payload_map(chat_id, recipient_user_id, recipient_device.device_id, db)
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

                for other_user_id in other_user_ids:
                    await manager.notify_user(other_user_id, {"type": "new_message", "chat_id": chat_id})
                    await manager.notify_user(other_user_id, {"type": "new_chat", "chat_id": chat_id})
                await manager.notify_user(user_id, {"type": "new_chat", "chat_id": chat_id})
                await notify_message_status(db, [msg])
                audit_logger.info(
                    "new_message_notified chat_id=%s recipient_user_ids=%s message_id=%s",
                    chat_id,
                    other_user_ids,
                    msg.id,
                )
    except WebSocketDisconnect:
        audit_logger.info("ws_chat_disconnected chat_id=%s user_id=%s", chat_id, user_id)
        manager.disconnect_chat(chat_id, websocket, user_id, device_id=device_id)


async def get_username(user_id: int, db: AsyncSession):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    return user.username if user else "Unknown"


async def build_chat_keys_payload(chat: Chat, current_user: User, db: AsyncSession, *, issue_prekeys: bool) -> dict:
    await ensure_direct_chat_participants_async(chat, db)
    participants = await get_chat_participants_async(chat.id, db)
    participant_user_ids = get_participant_user_ids(chat, participants)
    if current_user.id not in participant_user_ids:
        return {"status": "error", "message": "Chat not found or access denied."}

    other_user_ids = [user_id for user_id in participant_user_ids if user_id != current_user.id]
    if chat.is_group:
        users_result = await db.execute(select(User).where(User.id.in_(other_user_ids)))
        other_users = users_result.scalars().all()
        users_by_id = {user.id: user for user in other_users}

        flat_device_bundles = []
        participant_payloads = []
        for other_user_id in other_user_ids:
            other_user = users_by_id.get(other_user_id)
            if not other_user:
                continue
            if not has_complete_x3dh_bundle(other_user):
                return {"status": "error", "message": f"User {other_user.username} has not initialized X3DH keys yet."}
            devices = await get_active_devices_for_user(other_user.id, db)
            if not devices:
                return {"status": "error", "message": f"User {other_user.username} has no active devices."}
            bundles = [
                await (issue_device_prekey_bundle(device, db) if issue_prekeys else peek_device_prekey_bundle(device, db))
                for device in devices
            ]
            flat_device_bundles.extend(bundles)
            participant_payloads.append(
                {
                    "user_id": other_user.id,
                    "username": other_user.username,
                    "device_bundles": bundles,
                    **build_avatar_props(other_user),
                }
            )

        title = (chat.title or "Group chat").strip() or "Group chat"
        users_by_id = {user.id: user for user in other_users}
        current_user_db = await db.get(User, current_user.id)
        if current_user_db:
            users_by_id[current_user_db.id] = current_user_db
        return {
            "status": "ok",
            "is_group": True,
            "chat_id": chat.id,
            "username": title,
            "group_key_epoch": chat.group_key_epoch,
            "device_bundles": flat_device_bundles,
            "participants": participant_payloads,
            "members": [
                {
                    "user_id": participant.user_id,
                    "username": users_by_id[participant.user_id].username,
                    **build_avatar_props(users_by_id[participant.user_id]),
                }
                for participant in participants
                if participant.user_id in users_by_id
            ],
            "creator_id": chat.creator_id,
            **build_chat_avatar_props(chat),
        }

    other_user_id = get_direct_other_user_id(chat, current_user.id)
    if not other_user_id:
        return {"status": "error", "message": "Recipient was not found."}

    result = await db.execute(select(User).where(User.id == other_user_id))
    other_user = result.scalar_one_or_none()
    if not other_user:
        return {"status": "error", "message": "Recipient was not found."}
    if not has_complete_x3dh_bundle(other_user):
        return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

    active_devices = await get_active_devices_for_user(other_user.id, db)
    return {
        "status": "ok",
        "is_group": False,
        "identity_key": other_user.identity_key or "",
        "identity_signing_key": other_user.identity_signing_key or "",
        "prekey_bundle": await (issue_prekey_bundle(other_user.id, db) if issue_prekeys else peek_prekey_bundle(other_user.id, db)),
        "device_bundles": [
            await (issue_device_prekey_bundle(device, db) if issue_prekeys else peek_device_prekey_bundle(device, db))
            for device in active_devices
        ],
        "username": other_user.username,
        **build_avatar_props(other_user),
    }


async def get_deleted_message_ids(chat_id: int, user_id: int, db: AsyncSession) -> set[int]:
    result = await db.execute(
        select(DeletedMessage.message_id)
        .join(Message, Message.id == DeletedMessage.message_id)
        .where(DeletedMessage.user_id == user_id, Message.chat_id == chat_id)
    )
    return {message_id for message_id in result.scalars().all()}


def is_message_visible_to_user(
    message: Message,
    chat: Chat,
    user_id: int,
    deleted_message_ids: set[int],
    participant: ChatParticipant | None = None,
) -> bool:
    if message.deleted_for_all_at:
        return False
    if message.id in deleted_message_ids:
        return False
    if is_message_cleared_for_user(message, chat, user_id, participant):
        return False
    return True


@router.get("/messages/get_keys")
async def get_keys(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat:
            return {"status": "error", "message": "Chat not found or access denied."}

        payload = await build_chat_keys_payload(chat, current_user, db, issue_prekeys=False)
        if payload.get("status") != "ok":
            return payload
        if chat.is_group:
            return payload

        other_user_id = chat.user2_id if current_user.id == chat.user1_id else chat.user1_id
        result = await db.execute(select(User).where(User.id == other_user_id))
        other_user = result.scalar_one_or_none()
        if not other_user:
            return {"status": "error", "message": "Співрозмовник не знайдений"}

        if not has_complete_x3dh_bundle(other_user):
            return {"status": "error", "message": "Recipient X3DH keys are not initialized yet."}

        active_devices = await get_active_devices_for_user(other_user.id, db)

        return payload


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
        if not chat:
            return {"status": "error", "message": "Chat not found or access denied."}
        payload = await build_chat_keys_payload(chat, current_user, db, issue_prekeys=False)
        if payload.get("status") != "ok":
            return payload
        if chat.is_group:
            return payload

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
    recipient_user_ids: list[int],
    sender_device_id: str | None,
    parsed_payload,
):
    recipient_payloads = {}
    sender_payloads = {}

    if isinstance(parsed_payload, dict):
        recipient_payloads = normalize_device_payload_map(parsed_payload.get("device_payloads"))
        sender_payloads = normalize_device_payload_map(parsed_payload.get("sender_device_payloads"))

    sender_devices = await get_active_devices_for_user(sender_user_id, db)
    rows = []
    for recipient_user_id in recipient_user_ids:
        recipient_devices = await get_active_devices_for_user(recipient_user_id, db)
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
