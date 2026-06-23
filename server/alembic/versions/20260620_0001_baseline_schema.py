"""Baseline schema for secure chat application.

Revision ID: 20260620_0001
Revises: 
Create Date: 2026-06-20 00:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "20260620_0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("password", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("account_instance_id", sa.String(), nullable=False),
        sa.Column("avatar_filename", sa.String(), nullable=True),
        sa.Column("public_key", sa.Text(), nullable=True),
        sa.Column("identity_key", sa.Text(), nullable=True),
        sa.Column("signed_prekey", sa.Text(), nullable=True),
        sa.Column("signed_prekey_signature", sa.Text(), nullable=True),
        sa.Column("signed_prekey_key_id", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )

    op.create_table(
        "devices",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("device_name", sa.String(), nullable=False),
        sa.Column("identity_key", sa.Text(), nullable=True),
        sa.Column("identity_signing_key", sa.Text(), nullable=True),
        sa.Column("signed_prekey", sa.Text(), nullable=True),
        sa.Column("signed_prekey_signature", sa.Text(), nullable=True),
        sa.Column("signed_prekey_key_id", sa.Integer(), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id"),
    )
    op.create_index("ix_devices_user_id", "devices", ["user_id"], unique=False)
    op.create_index("ix_devices_device_id", "devices", ["device_id"], unique=True)

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("user_agent", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token"),
    )

    op.create_table(
        "encrypted_key_backups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index("ix_encrypted_key_backups_user_id", "encrypted_key_backups", ["user_id"], unique=True)

    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("token_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_id"),
    )
    op.create_index("ix_password_reset_tokens_token_id", "password_reset_tokens", ["token_id"], unique=True)
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"], unique=False)

    op.create_table(
        "chats",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user1_id", sa.Integer(), nullable=False),
        sa.Column("user2_id", sa.Integer(), nullable=True),
        sa.Column("is_group", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("title", sa.String(), nullable=True),
        sa.Column("avatar_filename", sa.String(), nullable=True),
        sa.Column("creator_id", sa.Integer(), nullable=True),
        sa.Column("group_key_epoch", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("pinned_message_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("user1_hidden", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("user2_hidden", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("user1_cleared_at", sa.DateTime(), nullable=True),
        sa.Column("user2_cleared_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["creator_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["user1_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["user2_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user1_id", "user2_id"),
    )

    op.create_table(
        "chat_participants",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("chat_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("hidden", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cleared_at", sa.DateTime(), nullable=True),
        sa.Column("joined_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["chat_id"], ["chats.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("chat_id", "user_id"),
    )
    op.create_index("ix_chat_participants_chat_id", "chat_participants", ["chat_id"], unique=False)
    op.create_index("ix_chat_participants_user_id", "chat_participants", ["user_id"], unique=False)

    op.create_table(
        "messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("chat_id", sa.Integer(), nullable=False),
        sa.Column("sender_id", sa.Integer(), nullable=False),
        sa.Column("sender_device_id", sa.String(), nullable=True),
        sa.Column("reply_to_message_id", sa.Integer(), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("attachment_kind", sa.String(), nullable=True),
        sa.Column("attachment_url", sa.String(), nullable=True),
        sa.Column("attachment_name", sa.String(), nullable=True),
        sa.Column("attachment_mime_type", sa.String(), nullable=True),
        sa.Column("attachment_size", sa.Integer(), nullable=True),
        sa.Column("attachment_meta", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("edited_at", sa.DateTime(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(), nullable=True),
        sa.Column("read_at", sa.DateTime(), nullable=True),
        sa.Column("deleted_for_all_at", sa.DateTime(), nullable=True),
        sa.Column("deleted_for_all_by_user_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["chat_id"], ["chats.id"]),
        sa.ForeignKeyConstraint(["reply_to_message_id"], ["messages.id"]),
        sa.ForeignKeyConstraint(["sender_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_foreign_key(
        "fk_chats_pinned_message_id_messages",
        "chats",
        "messages",
        ["pinned_message_id"],
        ["id"],
        use_alter=True,
    )

    op.create_table(
        "message_device_payloads",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("payload_role", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("message_id", "device_id", "payload_role"),
    )
    op.create_index("ix_message_device_payloads_message_id", "message_device_payloads", ["message_id"], unique=False)
    op.create_index("ix_message_device_payloads_user_id", "message_device_payloads", ["user_id"], unique=False)
    op.create_index("ix_message_device_payloads_device_id", "message_device_payloads", ["device_id"], unique=False)

    op.create_table(
        "deleted_messages",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("message_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["message_id"], ["messages.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "message_id"),
    )
    op.create_index("ix_deleted_messages_user_id", "deleted_messages", ["user_id"], unique=False)
    op.create_index("ix_deleted_messages_message_id", "deleted_messages", ["message_id"], unique=False)

    op.create_table(
        "one_time_prekeys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("key_id", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "key_id"),
    )
    op.create_index("ix_one_time_prekeys_user_id", "one_time_prekeys", ["user_id"], unique=False)

    op.create_table(
        "device_one_time_prekeys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("key_id", sa.Integer(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_id", "key_id"),
    )
    op.create_index("ix_device_one_time_prekeys_device_id", "device_one_time_prekeys", ["device_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_device_one_time_prekeys_device_id", table_name="device_one_time_prekeys")
    op.drop_table("device_one_time_prekeys")

    op.drop_index("ix_one_time_prekeys_user_id", table_name="one_time_prekeys")
    op.drop_table("one_time_prekeys")

    op.drop_index("ix_deleted_messages_message_id", table_name="deleted_messages")
    op.drop_index("ix_deleted_messages_user_id", table_name="deleted_messages")
    op.drop_table("deleted_messages")

    op.drop_index("ix_message_device_payloads_device_id", table_name="message_device_payloads")
    op.drop_index("ix_message_device_payloads_user_id", table_name="message_device_payloads")
    op.drop_index("ix_message_device_payloads_message_id", table_name="message_device_payloads")
    op.drop_table("message_device_payloads")

    op.drop_constraint("fk_chats_pinned_message_id_messages", "chats", type_="foreignkey")
    op.drop_table("messages")

    op.drop_index("ix_chat_participants_user_id", table_name="chat_participants")
    op.drop_index("ix_chat_participants_chat_id", table_name="chat_participants")
    op.drop_table("chat_participants")

    op.drop_table("chats")

    op.drop_index("ix_password_reset_tokens_user_id", table_name="password_reset_tokens")
    op.drop_index("ix_password_reset_tokens_token_id", table_name="password_reset_tokens")
    op.drop_table("password_reset_tokens")

    op.drop_index("ix_encrypted_key_backups_user_id", table_name="encrypted_key_backups")
    op.drop_table("encrypted_key_backups")

    op.drop_table("refresh_tokens")

    op.drop_index("ix_devices_device_id", table_name="devices")
    op.drop_index("ix_devices_user_id", table_name="devices")
    op.drop_table("devices")

    op.drop_table("users")
