from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, or_, and_
from sqlalchemy.orm import Session
from app.db.session import SessionLocal, AsyncSessionLocal
from datetime import datetime, timedelta

from app.db.models import Chat, Message, OneTimePreKey, User
from app.dependencies.auth import get_current_user
from app.utils.jwt import decode_access_token
from app.utils.time import utc_now
from app.utils.websocket_manager import manager
import os
from sqlalchemy.ext.asyncio import AsyncSession
router = APIRouter()
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))
USED_PREKEY_RETENTION_DAYS = 7


# ---------------- PAGE ----------------
@router.get("/messages", response_class=HTMLResponse)
def messages_page(request: Request, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()

    # 1️⃣ Вибираємо всі чати користувача
    chats = db.query(Chat).filter(
        or_(Chat.user1_id == current_user.id, Chat.user2_id == current_user.id)
    ).all()

    # 2️⃣ Дістаємо chat_id з query params (якщо є)
    chat_id = request.query_params.get("chat_id")
    other_public_key = None
    other_identity_key = None

    if chat_id:
        chat = db.query(Chat).filter(Chat.id == int(chat_id)).first()
        if chat:
            # визначаємо співрозмовника
            other_user_id = chat.user2_id if chat.user1_id == current_user.id else chat.user1_id
            other_user = db.query(User).filter(User.id == other_user_id).first()
            if other_user:
                other_public_key = other_user.public_key
                other_identity_key = other_user.identity_key

    db.close()

    # 3️⃣ Відправляємо шаблон із ключами співрозмовника
    return templates.TemplateResponse(
        request,
        "messages.html",
        {
            "request": request,
            "chats": chats,
            "current_user_id": current_user.id,
            "other_public_key": other_public_key,
            "other_identity_key": other_identity_key,
            "chat_id": chat_id
        }
    )
# ---------------- SEARCH USER ----------------
@router.get("/messages/search")
def search_users(query: str, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()

    users = db.query(User).filter(
        User.username.ilike(f"%{query}%"),
        User.id != current_user.id
    ).limit(10).all()

    db.close()

    return [
        {
            "id": u.id,
            "username": u.username
        }
        for u in users
    ]
# ---------------- START CHAT ----------------
@router.post("/messages/start")
async def start_chat_json(
    username: str = Form(...),   # 🔥 було email
    current_user: User = Depends(get_current_user)
):
    async with AsyncSessionLocal() as db:

        # 🔥 шукаємо користувача по username
        result = await db.execute(
            select(User).where(User.username == username)
        )
        other_user = result.scalar_one_or_none()

        if not other_user or other_user.id == current_user.id:
            return {"status": "error", "message": "Не знайдено користувача"}

        # 🔥 стабільний порядок id
        u1, u2 = sorted([current_user.id, other_user.id])

        # перевіряємо чи чат вже існує
        result = await db.execute(
            select(Chat).where(
                and_(Chat.user1_id == u1, Chat.user2_id == u2)
            )
        )
        chat = result.scalar_one_or_none()

        # якщо чату немає — створюємо
        is_new_chat = chat is None

        if not chat:
            chat = Chat(user1_id=u1, user2_id=u2)
            db.add(chat)
            await db.commit()
            await db.refresh(chat)

        return {
            "status": "ok",
            "chat_id": chat.id,
            "public_key": other_user.public_key,
            "identity_key": other_user.identity_key,
            "prekey_bundle": await (
                issue_prekey_bundle(other_user.id, db)
                if is_new_chat
                else peek_prekey_bundle(other_user.id, db)
            ),
            "username": other_user.username
        }
# ---------------- WEBSOCKET USER ----------------
@router.websocket("/ws/user")
async def websocket_user(websocket: WebSocket):

    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=1008)
        return

    payload = decode_access_token(token)
    if not payload:
        await websocket.close(code=1008)
        return

    email = payload.get("sub")

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user:
            await websocket.close(code=1008)
            return

        await manager.connect_user(user.id, websocket)

        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect_user(user.id, websocket)

# ---------------- WEBSOCKET CHAT ----------------
# ---------------- WEBSOCKET CHAT ----------------
@router.websocket("/ws/{chat_id}")
async def websocket_chat(websocket: WebSocket, chat_id: int):
    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close(code=1008)
        return

    payload = decode_access_token(token)
    if not payload:
        await websocket.close(code=1008)
        return

    email = payload.get("sub")
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if not user:
            await websocket.close(code=1008)
            return

        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or user.id not in [chat.user1_id, chat.user2_id]:
            await websocket.close(code=1008)
            return

        await manager.connect_chat(chat_id, websocket)

# Визначаємо співрозмовника
        other_user_id = chat.user2_id if user.id == chat.user1_id else chat.user1_id

        # 🔥 НАДСИЛАЄМО СТАТУС ТІЛЬКИ ОДИН РАЗ
        import json

        await websocket.send_text(json.dumps({
            "type": "status",
            "user_id": other_user_id,
            "is_online": manager.is_online(other_user_id)
        }))# 🔥 ОДРАЗУ НАДСИЛАЄМО ЙОГО СТАТУС
                

        # ---------------- ІСТОРІЯ ----------------
        result = await db.execute(
            select(Message)
            .where(Message.chat_id == chat_id)
            .order_by(Message.created_at)
        )
        messages = result.scalars().all()

        for msg in messages:
            sender_name = await get_username(msg.sender_id, db)
            await websocket.send_text(json.dumps({
            "type": "message",
            "message_id": msg.id,
            "sender": sender_name,
            "content": msg.content,
            "historical": True
        }))

        await websocket.send_text(json.dumps({
            "type": "history_complete"
        }))

        try:
            while True:
                data = await websocket.receive_text()

                # 🔥 Перевіряємо перше повідомлення
                result = await db.execute(
                    select(Message.id)
                    .where(Message.chat_id == chat_id)
                    .limit(1)
                )
                first_existing = result.scalar_one_or_none()
                is_first_message = first_existing is None

                msg = Message(chat_id=chat_id, sender_id=user.id, content=data)
                db.add(msg)
                await db.commit()
                await db.refresh(msg)

                await manager.broadcast_chat(chat_id, {
                "type": "message",
                "message_id": msg.id,
                "sender": user.username,
                "content": data,
                "historical": False
                })


                if is_first_message:
                    await manager.notify_user(other_user_id, {
                    "type": "new_chat"
                })

                await manager.notify_user(other_user_id, {
                "type": "new_message",
                "chat_id": chat_id
            })
        except WebSocketDisconnect:
            manager.disconnect_chat(chat_id, websocket)
# ---------------- HELPER ----------------
async def get_username(user_id: int, db: AsyncSession):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    return user.username if user else "Unknown"



@router.get("/messages/get_keys")
async def get_keys(chat_id: int, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        # Дістаємо чат
        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()
        if not chat or current_user.id not in [chat.user1_id, chat.user2_id]:
            return {"status": "error", "message": "Чат не знайдено або ви не учасник"}

        # Визначаємо співрозмовника
        other_user_id = chat.user2_id if current_user.id == chat.user1_id else chat.user1_id
        result = await db.execute(select(User).where(User.id == other_user_id))
        other_user = result.scalar_one_or_none()

        if not other_user:
            return {"status": "error", "message": "Співрозмовник не знайдений"}

        # 🔹 Повертаємо пусті ключі, якщо їх ще немає
        public_key = other_user.public_key or ""
        identity_key = other_user.identity_key or ""

        return {
            "status": "ok",
            "public_key": public_key,
            "identity_key": identity_key,
            "prekey_bundle": await peek_prekey_bundle(other_user.id, db),
            "username": other_user.username
        }


@router.get("/users/prekey-bundle")
async def get_prekey_bundle(username: str, current_user: User = Depends(get_current_user)):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == username))
        other_user = result.scalar_one_or_none()

        if not other_user or other_user.id == current_user.id:
            return {"status": "error", "message": "Користувача не знайдено"}

        return {
            "status": "ok",
            "username": other_user.username,
            "bundle": await issue_prekey_bundle(other_user.id, db)
        }
    

@router.get("/users/me")
def users_me(current_user: User = Depends(get_current_user)):
    return {"status": "ok", "username": current_user.username, "id": current_user.id}


async def issue_prekey_bundle(user_id: int, db: AsyncSession):
    await purge_old_used_prekeys(user_id, db)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return None

    result = await db.execute(
        select(OneTimePreKey)
        .where(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.used_at.is_(None)
        )
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
            "public_key": one_time_prekey.public_key
        }

    return {
        "identity_key": user.identity_key or user.public_key or "",
        "signing_key": user.signing_key or "",
        "signed_prekey": user.signed_prekey or "",
        "signed_prekey_signature": user.signed_prekey_signature or "",
        "signed_prekey_key_id": user.signed_prekey_key_id,
        "one_time_prekey": one_time_payload
    }


async def peek_prekey_bundle(user_id: int, db: AsyncSession):
    await purge_old_used_prekeys(user_id, db)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        return None

    result = await db.execute(
        select(OneTimePreKey)
        .where(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.used_at.is_(None)
        )
        .order_by(OneTimePreKey.id)
        .limit(1)
    )
    one_time_prekey = result.scalar_one_or_none()

    return {
        "identity_key": user.identity_key or user.public_key or "",
        "signing_key": user.signing_key or "",
        "signed_prekey": user.signed_prekey or "",
        "signed_prekey_signature": user.signed_prekey_signature or "",
        "signed_prekey_key_id": user.signed_prekey_key_id,
        "one_time_prekey": {
            "key_id": one_time_prekey.key_id,
            "public_key": one_time_prekey.public_key
        } if one_time_prekey else None
    }


async def purge_old_used_prekeys(user_id: int, db: AsyncSession):
    cutoff = utc_now() - timedelta(days=USED_PREKEY_RETENTION_DAYS)
    await db.execute(
        OneTimePreKey.__table__.delete().where(
            OneTimePreKey.user_id == user_id,
            OneTimePreKey.used_at.is_not(None),
            OneTimePreKey.used_at < cutoff
        )
    )
    await db.commit()
