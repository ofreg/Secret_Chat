import hashlib

from app.db.models import Chat, User

AVATAR_GRADIENT_CLASSES = [
    "avatar-gradient-1",
    "avatar-gradient-2",
    "avatar-gradient-3",
    "avatar-gradient-4",
    "avatar-gradient-5",
    "avatar-gradient-6",
    "avatar-gradient-7",
    "avatar-gradient-8",
    "avatar-gradient-9",
    "avatar-gradient-10",
    "avatar-gradient-11",
    "avatar-gradient-12",
]


def build_avatar_props(user: User | None) -> dict:
    if not user:
        return {
            "avatar_url": None,
            "avatar_class": _gradient_class("unknown"),
            "avatar_initial": "?",
        }

    seed = user.account_instance_id or user.email or user.username or str(user.id)
    avatar_url = f"/static/uploads/avatars/{user.avatar_filename}" if user.avatar_filename else None
    return {
        "avatar_url": avatar_url,
        "avatar_class": None if avatar_url else _gradient_class(seed),
        "avatar_initial": _build_initial(user),
    }


def build_chat_avatar_props(chat: Chat | None) -> dict:
    if not chat:
        return {
            "avatar_url": None,
            "avatar_class": _gradient_class("unknown-chat"),
            "avatar_initial": "#",
        }

    seed = chat.title or f"chat-{chat.id}"
    avatar_url = f"/static/uploads/avatars/{chat.avatar_filename}" if chat.avatar_filename else None
    title = (chat.title or "Group").strip()
    return {
        "avatar_url": avatar_url,
        "avatar_class": None if avatar_url else _gradient_class(seed),
        "avatar_initial": title[:1].upper() if title else "#",
    }


def _build_initial(user: User) -> str:
    source = (user.username or user.email or "?").strip()
    return source[:1].upper() if source else "?"


def _gradient_class(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    index = int(digest[0:8], 16) % len(AVATAR_GRADIENT_CLASSES)
    return AVATAR_GRADIENT_CLASSES[index]
