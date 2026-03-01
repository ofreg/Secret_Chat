from fastapi import WebSocket
from typing import Dict, List


class ConnectionManager:
    def __init__(self):
        # chat_id -> список websocket
        self.chat_connections: Dict[int, List[WebSocket]] = {}

        # user_id -> список websocket (кілька вкладок підтримуються)
        self.user_connections: Dict[int, List[WebSocket]] = {}

    # -------- USER SOCKET --------

    async def connect_user(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(websocket)

    def disconnect_user(self, user_id: int, websocket: WebSocket):
        if user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)
            if not self.user_connections[user_id]:
                self.user_connections.pop(user_id)

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