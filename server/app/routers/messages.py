from fastapi import APIRouter, Depends, Request, WebSocket, WebSocketDisconnect, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from app.db.session import AsyncSessionLocal, SessionLocal
from app.db.models import User, Chat, Message
from app.dependencies.auth import get_current_user
from app.utils.jwt import decode_access_token
import os

router = APIRouter()
templates = Jinja2Templates(
    directory=os.getenv("TEMPLATES_DIR", "/code/client/templates")
)

active_connections: dict[int, list[WebSocket]] = {}


# ---------------- PAGE ----------------

@router.get("/messages", response_class=HTMLResponse)
def messages_page(request: Request, current_user: User = Depends(get_current_user)):

    db: Session = SessionLocal()

    chats = db.query(Chat).filter(
        or_(
            Chat.user1_id == current_user.id,
            Chat.user2_id == current_user.id
        )
    ).all()

    db.close()

    return templates.TemplateResponse(
        "messages.html",
        {
            "request": request,
            "chats": chats,
            "current_user_id": current_user.id
        }
    )


# ---------------- SEARCH USER ----------------

@router.post("/messages/start")
def start_chat(
    email: str = Form(...),
    current_user: User = Depends(get_current_user)
):

    db: Session = SessionLocal()

    other_user = db.query(User).filter(User.email == email).first()

    if not other_user or other_user.id == current_user.id:
        db.close()
        return RedirectResponse("/messages", status_code=303)

    u1, u2 = sorted([current_user.id, other_user.id])

    chat = db.query(Chat).filter(
        and_(Chat.user1_id == u1, Chat.user2_id == u2)
    ).first()

    if not chat:
        chat = Chat(user1_id=u1, user2_id=u2)
        db.add(chat)
        db.commit()
        db.refresh(chat)

    db.close()

    return RedirectResponse(f"/messages?chat_id={chat.id}", status_code=303)

@router.get("/messages/search")
def search_users(
    query: str,
    current_user: User = Depends(get_current_user)
):
    db: Session = SessionLocal()

    users = db.query(User).filter(
        User.email.ilike(f"%{query}%"),
        User.id != current_user.id
    ).limit(10).all()

    db.close()

    return [
        {"id": user.id, "email": user.email}
        for user in users
    ]
# ---------------- WEBSOCKET ----------------

@router.websocket("/ws/{chat_id}")
async def websocket_endpoint(websocket: WebSocket, chat_id: int):

    token = websocket.cookies.get("access_token")
    if not token:
        await websocket.close()
        return

    payload = decode_access_token(token)
    if not payload:
        await websocket.close()
        return

    email = payload.get("sub")

    async with AsyncSessionLocal() as db:

        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user:
            await websocket.close()
            return

        result = await db.execute(select(Chat).where(Chat.id == chat_id))
        chat = result.scalar_one_or_none()

        if not chat or user.id not in [chat.user1_id, chat.user2_id]:
            await websocket.close()
            return

        await websocket.accept()

        # Підключення
        if chat_id not in active_connections:
            active_connections[chat_id] = []

        active_connections[chat_id].append(websocket)

        # 🔹 Надсилаємо історію
        result = await db.execute(
            select(Message).where(Message.chat_id == chat_id).order_by(Message.created_at)
        )
        messages = result.scalars().all()

        for msg in messages:
            await websocket.send_text(f"{msg.sender_id}: {msg.content}")

        try:
            while True:
                data = await websocket.receive_text()

                msg = Message(
                    chat_id=chat_id,
                    sender_id=user.id,
                    content=data
                )

                db.add(msg)
                await db.commit()

                for connection in active_connections[chat_id]:
                    await connection.send_text(f"{user.id}: {data}")

        except WebSocketDisconnect:
            active_connections[chat_id].remove(websocket)