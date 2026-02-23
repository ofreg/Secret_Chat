from fastapi import WebSocket
from typing import Dict, List


class ConnectionManager:
    def __init__(self):
        # чат -> список websocket
        self.chat_connections: Dict[int, List[WebSocket]] = {}

        # user_id -> websocket
        self.user_connections: Dict[int, WebSocket] = {}

    # -------- USER SOCKET --------

    async def connect_user(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        self.user_connections[user_id] = websocket

    def disconnect_user(self, user_id: int):
        self.user_connections.pop(user_id, None)

    async def notify_user(self, user_id: int, message: str):
        if user_id in self.user_connections:
            await self.user_connections[user_id].send_text(message)

    # -------- CHAT SOCKET --------

    async def connect_chat(self, chat_id: int, websocket: WebSocket):
        await websocket.accept()
        if chat_id not in self.chat_connections:
            self.chat_connections[chat_id] = []
        self.chat_connections[chat_id].append(websocket)

    def disconnect_chat(self, chat_id: int, websocket: WebSocket):
        if chat_id in self.chat_connections:
            self.chat_connections[chat_id].remove(websocket)

    async def broadcast_chat(self, chat_id: int, message: str):
        for connection in self.chat_connections.get(chat_id, []):
            await connection.send_text(message)