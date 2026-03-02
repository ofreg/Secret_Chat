from fastapi import WebSocket
from typing import Dict, List
import asyncio


class ConnectionManager:
    def __init__(self):
        # chat_id -> список websocket (відкриті чати)
        self.chat_connections: Dict[int, List[WebSocket]] = {}

        # user_id -> список websocket (меню /ws/user)
        self.user_connections: Dict[int, List[WebSocket]] = {}

        # онлайн користувачі
        self.online_users: set[int] = set()

    # -------- USER SOCKET --------

    async def connect_user(self, user_id: int, websocket: WebSocket):
        await websocket.accept()

        if user_id not in self.user_connections:
            self.user_connections[user_id] = []

        self.user_connections[user_id].append(websocket)

        # якщо це перша вкладка — користувач став онлайн
        if len(self.user_connections[user_id]) == 1:
            self.online_users.add(user_id)
            await self.broadcast_user_status(user_id, True)

    def disconnect_user(self, user_id: int, websocket: WebSocket):
        if user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)

            # якщо вкладок більше нема — офлайн
            if not self.user_connections[user_id]:
                self.user_connections.pop(user_id)
                self.online_users.discard(user_id)

                asyncio.create_task(
                    self.broadcast_user_status(user_id, False)
                )

    def is_online(self, user_id: int) -> bool:
        return user_id in self.online_users

    async def notify_user(self, user_id: int, message: str):
        for websocket in list(self.user_connections.get(user_id, [])):
            try:
                await websocket.send_text(message)
            except:
                self.disconnect_user(user_id, websocket)

    # -------- CHAT SOCKET --------

    async def connect_chat(self, chat_id: int, websocket: WebSocket):
        await websocket.accept()

        if chat_id not in self.chat_connections:
            self.chat_connections[chat_id] = []

        self.chat_connections[chat_id].append(websocket)

    def disconnect_chat(self, chat_id: int, websocket: WebSocket):
        if chat_id in self.chat_connections:
            if websocket in self.chat_connections[chat_id]:
                self.chat_connections[chat_id].remove(websocket)

            if not self.chat_connections[chat_id]:
                self.chat_connections.pop(chat_id)

    async def broadcast_chat(self, chat_id: int, message: str):
        for connection in list(self.chat_connections.get(chat_id, [])):
            try:
                await connection.send_text(message)
            except:
                self.disconnect_chat(chat_id, connection)

    # -------- STATUS BROADCAST --------

    async def broadcast_user_status(self, user_id: int, is_online: bool):

        status_message = "user_online" if is_online else "user_offline"

        # 1️⃣ Оновлюємо user websocket (меню)
        for uid in list(self.user_connections.keys()):
            if uid != user_id:
                await self.notify_user(uid, status_message)

        # 2️⃣ Оновлюємо відкриті чати
        for chat_id, sockets in self.chat_connections.items():
            for ws in list(sockets):
                try:
                    await ws.send_text(status_message)
                except:
                    self.disconnect_chat(chat_id, ws)


# 🔥 ГОЛОВНЕ — один глобальний manager
manager = ConnectionManager()