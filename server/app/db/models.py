from datetime import datetime
import uuid

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base
from app.utils.time import utc_now


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True)
    password: Mapped[str] = mapped_column(String)

    username: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    account_instance_id: Mapped[str] = mapped_column(
        String,
        nullable=False,
        default=lambda: uuid.uuid4().hex,
    )
    avatar_filename: Mapped[str] = mapped_column(String, nullable=True)
    identity_key: Mapped[str] = mapped_column("public_key", Text, nullable=True)
    identity_signing_key: Mapped[str] = mapped_column("identity_key", Text, nullable=True)
    signed_prekey: Mapped[str] = mapped_column(Text, nullable=True)
    signed_prekey_signature: Mapped[str] = mapped_column(Text, nullable=True)
    signed_prekey_key_id: Mapped[int] = mapped_column(Integer, nullable=True)


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    device_name: Mapped[str] = mapped_column(String, nullable=False, default="Browser device")
    identity_key: Mapped[str] = mapped_column(Text, nullable=True)
    identity_signing_key: Mapped[str] = mapped_column(Text, nullable=True)
    signed_prekey: Mapped[str] = mapped_column(Text, nullable=True)
    signed_prekey_signature: Mapped[str] = mapped_column(Text, nullable=True)
    signed_prekey_key_id: Mapped[int] = mapped_column(Integer, nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship("User")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String, unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime)

    user_agent: Mapped[str] = mapped_column(String, nullable=True)
    ip_address: Mapped[str] = mapped_column(String, nullable=True)


class EncryptedKeyBackup(Base):
    __tablename__ = "encrypted_key_backups"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, onupdate=utc_now)

    user: Mapped["User"] = relationship("User")


class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    token_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)


class Chat(Base):
    __tablename__ = "chats"

    id: Mapped[int] = mapped_column(primary_key=True)

    user1_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    user2_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    user1: Mapped["User"] = relationship("User", foreign_keys=[user1_id])
    user2: Mapped["User"] = relationship("User", foreign_keys=[user2_id])

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    user1_hidden: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user2_hidden: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user1_cleared_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    user2_cleared_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("user1_id", "user2_id"),
    )


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(primary_key=True)

    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    sender_device_id: Mapped[str] = mapped_column(String, nullable=True)

    content: Mapped[str] = mapped_column(Text)
    attachment_kind: Mapped[str] = mapped_column(String, nullable=True)
    attachment_url: Mapped[str] = mapped_column(String, nullable=True)
    attachment_name: Mapped[str] = mapped_column(String, nullable=True)
    attachment_mime_type: Mapped[str] = mapped_column(String, nullable=True)
    attachment_size: Mapped[int] = mapped_column(Integer, nullable=True)
    attachment_meta: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    delivered_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    read_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    deleted_for_all_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    deleted_for_all_by_user_id: Mapped[int] = mapped_column(Integer, nullable=True)


class MessageDevicePayload(Base):
    __tablename__ = "message_device_payloads"

    id: Mapped[int] = mapped_column(primary_key=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    device_id: Mapped[str] = mapped_column(String, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    payload_role: Mapped[str] = mapped_column(String, nullable=False, default="shared")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    __table_args__ = (
        UniqueConstraint("message_id", "device_id", "payload_role"),
    )


class DeletedMessage(Base):
    __tablename__ = "deleted_messages"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)

    __table_args__ = (
        UniqueConstraint("user_id", "message_id"),
    )


class OneTimePreKey(Base):
    __tablename__ = "one_time_prekeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    key_id: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship("User")

    __table_args__ = (
        UniqueConstraint("user_id", "key_id"),
    )


class DeviceOneTimePreKey(Base):
    __tablename__ = "device_one_time_prekeys"

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[str] = mapped_column(String, index=True)
    key_id: Mapped[int] = mapped_column(Integer, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    __table_args__ = (
        UniqueConstraint("device_id", "key_id"),
    )
