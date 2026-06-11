import io

from app.db.models import Chat, DeletedMessage, Message
from app.utils.time import utc_now
from tests.helpers import login_user, register_user, upload_x3dh_keys


def test_protected_message_routes_require_authentication(client):
    protected_get_routes = [
        ("/messages", None),
        ("/messages/search", {"query": "user"}),
        ("/messages/get_keys", {"chat_id": 1}),
        ("/users/prekey-bundle", {"username": "user2"}),
        ("/users/me", None),
    ]

    for path, params in protected_get_routes:
        response = client.get(path, params=params)
        assert response.status_code == 401, path

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 401


def test_messages_endpoints_and_chat_bootstrap(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    assert upload_x3dh_keys(
        second_client,
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[
            {"key_id": 1001, "public_key": "otpk-user2-1"},
            {"key_id": 1002, "public_key": "otpk-user2-2"},
        ],
    ).status_code == 200

    response = client.get("/messages/search", params={"query": "user2"})
    assert response.status_code == 200
    assert response.json()[0]["id"] == 2
    assert response.json()[0]["username"] == "user2"
    assert response.json()[0]["avatar_url"] is None
    assert response.json()[0]["avatar_class"].startswith("avatar-gradient-")
    assert response.json()[0]["avatar_initial"] == "U"

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["chat_id"] == 1
    assert payload["identity_key"] == "public-key-user2"
    assert payload["identity_signing_key"] == "identity-signing-user2"
    assert payload["username"] == "user2"
    assert payload["avatar_url"] is None
    assert payload["avatar_class"].startswith("avatar-gradient-")
    assert payload["avatar_initial"] == "U"
    assert payload["prekey_bundle"] == {
        "identity_key": "public-key-user2",
        "identity_signing_key": "identity-signing-user2",
        "signed_prekey": "signed-prekey-user2",
        "signed_prekey_signature": "signed-prekey-signature-user2",
        "signed_prekey_key_id": 101,
        "one_time_prekey": {"key_id": 1001, "public_key": "otpk-user2-1"},
    }

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["chat_id"] == 1
    assert payload["prekey_bundle"] == {
        "identity_key": "public-key-user2",
        "identity_signing_key": "identity-signing-user2",
        "signed_prekey": "signed-prekey-user2",
        "signed_prekey_signature": "signed-prekey-signature-user2",
        "signed_prekey_key_id": 101,
        "one_time_prekey": {"key_id": 1002, "public_key": "otpk-user2-2"},
    }

    response = client.get("/messages/get_keys", params={"chat_id": 1})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["identity_key"] == "public-key-user2"
    assert payload["identity_signing_key"] == "identity-signing-user2"
    assert payload["username"] == "user2"
    assert payload["avatar_url"] is None
    assert payload["avatar_class"].startswith("avatar-gradient-")
    assert payload["avatar_initial"] == "U"
    assert payload["prekey_bundle"] == {
        "identity_key": "public-key-user2",
        "identity_signing_key": "identity-signing-user2",
        "signed_prekey": "signed-prekey-user2",
        "signed_prekey_signature": "signed-prekey-signature-user2",
        "signed_prekey_key_id": 101,
        "one_time_prekey": {"key_id": 1002, "public_key": "otpk-user2-2"},
    }

    response = client.get("/users/prekey-bundle", params={"username": "user2"})
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "username": "user2",
        "bundle": {
            "identity_key": "public-key-user2",
            "identity_signing_key": "identity-signing-user2",
            "signed_prekey": "signed-prekey-user2",
            "signed_prekey_signature": "signed-prekey-signature-user2",
            "signed_prekey_key_id": 101,
            "one_time_prekey": {"key_id": 1002, "public_key": "otpk-user2-2"},
        },
    }

    response = client.get("/users/device-prekey-bundles", params={"username": "user2"})
    assert response.status_code == 200
    device_payload = response.json()
    assert device_payload["status"] == "ok"
    assert device_payload["username"] == "user2"
    assert len(device_payload["devices"]) == 1
    assert device_payload["devices"][0]["device_id"]
    assert device_payload["devices"][0]["identity_key"] == "public-key-user2"

    response = client.get("/users/prekey-bundle", params={"username": "user2"})
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "username": "user2",
        "bundle": {
            "identity_key": "public-key-user2",
            "identity_signing_key": "identity-signing-user2",
            "signed_prekey": "signed-prekey-user2",
            "signed_prekey_signature": "signed-prekey-signature-user2",
            "signed_prekey_key_id": 101,
            "one_time_prekey": None,
        },
    }

    assert upload_x3dh_keys(
        second_client,
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2-v2",
        signed_prekey_signature="signed-prekey-signature-user2-v2",
        signed_prekey_key_id=202,
        one_time_prekeys=[],
    ).status_code == 200

    response = client.get("/users/prekey-bundle", params={"username": "user2"})
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "username": "user2",
        "bundle": {
            "identity_key": "public-key-user2",
            "identity_signing_key": "identity-signing-user2",
            "signed_prekey": "signed-prekey-user2-v2",
            "signed_prekey_signature": "signed-prekey-signature-user2-v2",
            "signed_prekey_key_id": 202,
            "one_time_prekey": None,
        },
    }

    response = client.get("/messages", params={"chat_id": 1})
    assert response.status_code == 200
    assert "/static/js/messages.js" in response.text
    assert "public-key-user2" in response.text


def test_messages_key_endpoints_require_complete_x3dh_bundle(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    invalid_upload_response = second_client.post(
        "/users/x3dh-keys",
        json={
            "identity_key": "",
            "identity_signing_key": "identity-signing-user2-only",
            "signed_prekey": "signed-prekey-user2",
            "signed_prekey_signature": "signed-prekey-signature-user2",
            "signed_prekey_key_id": 101,
            "one_time_prekeys": [],
        },
    )
    assert invalid_upload_response.status_code == 422

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 200
    payload = response.json()
    assert payload == {
        "status": "error",
        "message": "Recipient X3DH keys are not initialized yet.",
    }


def test_message_attachment_upload(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_x3dh_keys(
        second_client,
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 200
    chat_id = response.json()["chat_id"]

    upload_response = client.post(
        "/messages/upload",
        data={"chat_id": str(chat_id)},
        files={"file": ("photo.png", io.BytesIO(b"fake-image-bytes"), "image/png")},
    )
    assert upload_response.status_code == 200
    payload = upload_response.json()
    assert payload["status"] == "ok"
    assert payload["attachment"]["kind"] == "image"
    assert payload["attachment"]["name"] == "photo.png"
    assert payload["attachment"]["mime_type"] == "image/png"
    assert payload["attachment"]["size"] == len(b"fake-image-bytes")
    assert payload["attachment"]["url"].startswith("/static/uploads/messages/")


def test_encrypted_message_attachment_upload_hides_plain_metadata(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_x3dh_keys(
        second_client,
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 200
    chat_id = response.json()["chat_id"]

    upload_response = client.post(
        "/messages/upload",
        data={"chat_id": str(chat_id), "encrypted": "true"},
        files={"file": ("attachment.bin", io.BytesIO(b"encrypted-media-bytes"), "application/octet-stream")},
    )
    assert upload_response.status_code == 200
    payload = upload_response.json()
    assert payload["status"] == "ok"
    assert payload["attachment"] == {
        "kind": "encrypted",
        "name": "encrypted-media.bin",
        "mime_type": "application/octet-stream",
        "size": len(b"encrypted-media-bytes"),
        "url": payload["attachment"]["url"],
    }
    assert payload["attachment"]["url"].startswith("/static/uploads/messages/")


def test_security_headers_present_on_messages_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in response.headers["Permissions-Policy"]


def test_message_delete_self_and_all_endpoints(client, second_client, db_session):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303
    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    chat = Chat(user1_id=1, user2_id=2)
    db_session.add(chat)
    db_session.commit()
    db_session.refresh(chat)

    own_message = Message(chat_id=chat.id, sender_id=1, content="cipher-own")
    peer_message = Message(chat_id=chat.id, sender_id=2, content="cipher-peer")
    db_session.add_all([own_message, peer_message])
    db_session.commit()
    db_session.refresh(own_message)
    db_session.refresh(peer_message)

    response = client.post(f"/messages/{peer_message.id}/delete-self")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    deleted_row = (
        db_session.query(DeletedMessage)
        .filter(DeletedMessage.user_id == 1, DeletedMessage.message_id == peer_message.id)
        .first()
    )
    assert deleted_row is not None

    response = client.post(f"/messages/{own_message.id}/delete-all")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    db_session.refresh(own_message)
    assert own_message.deleted_for_all_at is not None
    assert own_message.deleted_for_all_by_user_id == 1
    assert own_message.attachment_url is None


def test_chat_delete_and_restart_reuses_existing_chat(client, second_client, db_session):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303
    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    assert upload_x3dh_keys(
        client,
        identity_key="public-key-user1",
        identity_signing_key="identity-signing-user1",
        signed_prekey="signed-prekey-user1",
        signed_prekey_signature="signed-prekey-signature-user1",
        signed_prekey_key_id=201,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        second_client,
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200

    start_response = client.post("/messages/start", data={"username": "user2"})
    assert start_response.status_code == 200
    chat_id = start_response.json()["chat_id"]

    chat = db_session.query(Chat).filter(Chat.id == chat_id).first()
    assert chat is not None
    db_session.add(Message(chat_id=chat_id, sender_id=1, content="cipher-history", created_at=utc_now()))
    db_session.commit()

    response = client.post(f"/chats/{chat_id}/delete-self")
    assert response.status_code == 200
    db_session.refresh(chat)
    assert chat.user1_hidden is True
    assert chat.user1_cleared_at is not None

    messages_page = client.get("/messages")
    assert messages_page.status_code == 200
    assert f"/messages?chat_id={chat_id}" not in messages_page.text

    restart_response = client.post("/messages/start", data={"username": "user2"})
    assert restart_response.status_code == 200
    assert restart_response.json()["chat_id"] == chat_id

    db_session.refresh(chat)
    assert chat.user1_hidden is False
    assert chat.user1_cleared_at is not None

    response = client.post(f"/chats/{chat_id}/delete-all")
    assert response.status_code == 200
    db_session.refresh(chat)
    assert chat.user1_hidden is True
    assert chat.user2_hidden is True
    assert chat.user1_cleared_at is not None
    assert chat.user2_cleared_at is not None

    second_start = second_client.post("/messages/start", data={"username": "user1"})
    assert second_start.status_code == 200
    assert second_start.json()["chat_id"] == chat_id
