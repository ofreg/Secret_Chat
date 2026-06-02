import asyncio
import json
from typing import Dict, List

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.chat_connections: Dict[int, List[WebSocket]] = {}
        self.chat_user_connections: Dict[int, Dict[int, List[WebSocket]]] = {}
        self.chat_device_connections: Dict[int, Dict[str, List[WebSocket]]] = {}
        self.user_connections: Dict[int, List[WebSocket]] = {}
        self.user_device_connections: Dict[int, Dict[str, List[WebSocket]]] = {}
        self.online_users: set[int] = set()

    async def safe_send(self, websocket: WebSocket, data: dict):
        try:
            await websocket.send_text(json.dumps(data))
            return True
        except Exception:
            return False

    async def connect_user(self, user_id: int, websocket: WebSocket, device_id: str | None = None):
        await websocket.accept()

        if user_id not in self.user_connections:
            self.user_connections[user_id] = []
        self.user_connections[user_id].append(websocket)

        if device_id:
            if user_id not in self.user_device_connections:
                self.user_device_connections[user_id] = {}
            if device_id not in self.user_device_connections[user_id]:
                self.user_device_connections[user_id][device_id] = []
            self.user_device_connections[user_id][device_id].append(websocket)

        if len(self.user_connections[user_id]) == 1:
            self.online_users.add(user_id)
            await self.broadcast_user_status(user_id, True)

    def disconnect_user(self, user_id: int, websocket: WebSocket, device_id: str | None = None):
        if user_id in self.user_connections:
            if websocket in self.user_connections[user_id]:
                self.user_connections[user_id].remove(websocket)

            if not self.user_connections[user_id]:
                self.user_connections.pop(user_id)
                self.online_users.discard(user_id)
                asyncio.create_task(self.broadcast_user_status(user_id, False))

        if device_id and user_id in self.user_device_connections:
            device_sockets = self.user_device_connections[user_id].get(device_id, [])
            if websocket in device_sockets:
                device_sockets.remove(websocket)
            if not device_sockets and device_id in self.user_device_connections[user_id]:
                self.user_device_connections[user_id].pop(device_id)
            if not self.user_device_connections[user_id]:
                self.user_device_connections.pop(user_id)

    def is_online(self, user_id: int) -> bool:
        return user_id in self.online_users

    async def notify_user(self, user_id: int, data: dict):
        for websocket in list(self.user_connections.get(user_id, [])):
            ok = await self.safe_send(websocket, data)
            if not ok:
                self.disconnect_user(user_id, websocket)

    async def notify_user_device(self, user_id: int, device_id: str, data: dict):
        for websocket in list(self.user_device_connections.get(user_id, {}).get(device_id, [])):
            ok = await self.safe_send(websocket, data)
            if not ok:
                self.disconnect_user(user_id, websocket, device_id=device_id)

    async def connect_chat(self, chat_id: int, user_id: int, websocket: WebSocket, device_id: str | None = None):
        await websocket.accept()

        if chat_id not in self.chat_connections:
            self.chat_connections[chat_id] = []
        if chat_id not in self.chat_user_connections:
            self.chat_user_connections[chat_id] = {}
        if chat_id not in self.chat_device_connections:
            self.chat_device_connections[chat_id] = {}
        if user_id not in self.chat_user_connections[chat_id]:
            self.chat_user_connections[chat_id][user_id] = []

        self.chat_connections[chat_id].append(websocket)
        self.chat_user_connections[chat_id][user_id].append(websocket)

        if device_id:
            if device_id not in self.chat_device_connections[chat_id]:
                self.chat_device_connections[chat_id][device_id] = []
            self.chat_device_connections[chat_id][device_id].append(websocket)

    def disconnect_chat(self, chat_id: int, websocket: WebSocket, user_id: int | None = None, device_id: str | None = None):
        if chat_id in self.chat_connections:
            if websocket in self.chat_connections[chat_id]:
                self.chat_connections[chat_id].remove(websocket)

            if not self.chat_connections[chat_id]:
                self.chat_connections.pop(chat_id)

        if user_id is not None and chat_id in self.chat_user_connections:
            user_sockets = self.chat_user_connections[chat_id].get(user_id, [])
            if websocket in user_sockets:
                user_sockets.remove(websocket)
            if not user_sockets and user_id in self.chat_user_connections[chat_id]:
                self.chat_user_connections[chat_id].pop(user_id)
            if not self.chat_user_connections[chat_id]:
                self.chat_user_connections.pop(chat_id)

        if device_id is not None and chat_id in self.chat_device_connections:
            device_sockets = self.chat_device_connections[chat_id].get(device_id, [])
            if websocket in device_sockets:
                device_sockets.remove(websocket)
            if not device_sockets and device_id in self.chat_device_connections[chat_id]:
                self.chat_device_connections[chat_id].pop(device_id)
            if not self.chat_device_connections[chat_id]:
                self.chat_device_connections.pop(chat_id)

    def has_chat_user(self, chat_id: int, user_id: int) -> bool:
        return bool(self.chat_user_connections.get(chat_id, {}).get(user_id))

    async def broadcast_chat(self, chat_id: int, data: dict):
        for connection in list(self.chat_connections.get(chat_id, [])):
            ok = await self.safe_send(connection, data)
            if not ok:
                self.disconnect_chat(chat_id, connection)

    async def notify_chat_device(self, chat_id: int, device_id: str, data: dict):
        for websocket in list(self.chat_device_connections.get(chat_id, {}).get(device_id, [])):
            ok = await self.safe_send(websocket, data)
            if not ok:
                self.disconnect_chat(chat_id, websocket, device_id=device_id)

    async def notify_chat_user(self, chat_id: int, user_id: int, data: dict, *, exclude: WebSocket | None = None):
        for websocket in list(self.chat_user_connections.get(chat_id, {}).get(user_id, [])):
            if exclude is not None and websocket is exclude:
                continue
            ok = await self.safe_send(websocket, data)
            if not ok:
                self.disconnect_chat(chat_id, websocket, user_id=user_id)

    async def broadcast_user_status(self, user_id: int, is_online: bool):
        data = {
            "type": "status",
            "user_id": user_id,
            "is_online": is_online
        }

        tasks = []

        for uid in list(self.user_connections.keys()):
            if uid != user_id:
                tasks.append(self.notify_user(uid, data))

        for chat_id, sockets in list(self.chat_connections.items()):
            for ws in list(sockets):
                async def send(ws=ws, chat_id=chat_id):
                    ok = await self.safe_send(ws, data)
                    if not ok:
                        self.disconnect_chat(chat_id, ws)
                tasks.append(send())

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


manager = ConnectionManager()
