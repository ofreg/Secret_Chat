from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, or_, and_
from sqlalchemy.orm import Session
from app.db.session import SessionLocal, AsyncSessionLocal
from app.db.models import User, Chat, Message
from app.dependencies.auth import get_current_user
from app.utils.jwt import decode_access_token
from app.utils.websocket_manager import manager
import os

router = APIRouter()
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))


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
    users = db.query(User).filter(User.email.ilike(f"%{query}%"), User.id != current_user.id).limit(10).all()
    db.close()
    return [{"id": u.id, "email": u.email} for u in users]

# ---------------- START CHAT ----------------
@router.post("/messages/start")
async def start_chat_json(
    email: str = Form(...),
    current_user: User = Depends(get_current_user)
):
    async with AsyncSessionLocal() as db:

        result = await db.execute(select(User).where(User.email == email))
        other_user = result.scalar_one_or_none()

        if not other_user or other_user.id == current_user.id:
            return {"status": "error", "message": "Не знайдено користувача"}

        u1, u2 = sorted([current_user.id, other_user.id])

        result = await db.execute(
            select(Chat).where(and_(Chat.user1_id == u1, Chat.user2_id == u2))
        )
        chat = result.scalar_one_or_none()

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
            "sender": sender_name,
            "content": msg.content
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

                await manager.broadcast_chat(chat_id, {
                "type": "message",
                "sender": user.username,
                "content": data
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
async def get_username(user_id: int, db: AsyncSessionLocal):
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
            "username": other_user.username
        }