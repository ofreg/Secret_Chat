import pytest
from fastapi.testclient import TestClient
from queue import Queue
from threading import Thread
from queue import Empty

from app.db.models import Message, MessageDevicePayload
from app.db.session import SessionLocal
from tests.helpers import login_user, register_user, upload_x3dh_keys


def receive_json_with_timeout(websocket, timeout: float = 5.0):
    queue: Queue = Queue(maxsize=1)

    def worker():
        try:
            queue.put(("ok", websocket.receive_json()))
        except Exception as error:
            queue.put(("error", error))

    Thread(target=worker, daemon=True).start()

    try:
        status, value = queue.get(timeout=timeout)
    except Empty as error:
        raise AssertionError(f"Timed out waiting for websocket event after {timeout} seconds") from error

    if status == "error":
        raise value
    return value


def receive_until_type(websocket, expected_type: str):
    while True:
        payload = receive_json_with_timeout(websocket)
        if payload.get("type") == expected_type:
            return payload


def assert_message_payload_contains(actual_payload, expected_payload):
    for key, expected_value in expected_payload.items():
        assert actual_payload.get(key) == expected_value

    assert "created_at" in actual_payload
    assert "read_at" in actual_payload


def upload_default_x3dh_bundle(test_client):
    return upload_x3dh_keys(
        test_client,
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    )


def test_websocket_routes_require_valid_session(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/user"):
            assert False, "Anonymous websocket connection should not stay open"

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/1"):
            assert False, "Anonymous chat websocket connection should not stay open"


def test_websocket_chat_delivery_and_message_persistence(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_default_x3dh_bundle(second_client).status_code == 200

    create_chat_response = client.post("/messages/start", data={"username": "user2"})
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    message_payload = '{"version":2,"recipient":{"epk":"r1","nonce":"n1","message":"m1"},"sender":{"epk":"r2","nonce":"n2","message":"m2"}}'

    with second_client.websocket_connect("/ws/user") as user_ws:
        with client.websocket_connect(f"/ws/{chat_id}") as sender_ws:
            sender_status = receive_json_with_timeout(sender_ws)
            assert sender_status["type"] == "status"
            assert sender_status["is_online"] is True
            assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}

            with second_client.websocket_connect(f"/ws/{chat_id}") as receiver_ws:
                receiver_status = receive_json_with_timeout(receiver_ws)
                assert receiver_status["type"] == "status"
                assert receive_json_with_timeout(receiver_ws) == {"type": "history_complete"}

                sender_ws.send_text(message_payload)

                sender_message = receive_until_type(sender_ws, "message")
                receiver_message = receive_until_type(receiver_ws, "message")
                first_notification = receive_json_with_timeout(user_ws)

    assert_message_payload_contains(sender_message, {
        "type": "message",
        "message_id": 1,
        "reply_to_message_id": None,
        "sender": "user1",
        "sender_device_id": None,
        "content": message_payload,
        "historical": False,
        "delivery_status": "read",
        "attachment": None,
        "deleted_for_all": False,
    })
    assert receiver_message == sender_message
    assert first_notification == {"type": "new_message", "chat_id": chat_id}

    db_session = SessionLocal()
    try:
        saved_message = db_session.query(Message).filter(Message.chat_id == chat_id).one()
        assert saved_message.sender_id == 1
        assert saved_message.content == message_payload
        assert saved_message.delivered_at is not None
        assert saved_message.read_at is not None
    finally:
        db_session.close()

    with second_client.websocket_connect(f"/ws/{chat_id}") as history_ws:
        history_status = receive_json_with_timeout(history_ws)
        history_message = receive_until_type(history_ws, "message")
        history_complete = receive_json_with_timeout(history_ws)

    assert history_status["type"] == "status"
    assert_message_payload_contains(history_message, {
        "type": "message",
        "message_id": 1,
        "reply_to_message_id": None,
        "sender": "user1",
        "sender_device_id": None,
        "content": message_payload,
        "historical": True,
        "delivery_status": "read",
        "attachment": None,
        "deleted_for_all": False,
    })
    assert history_complete == {"type": "history_complete"}


def test_websocket_chat_history_reconnect_preserves_order(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_default_x3dh_bundle(second_client).status_code == 200

    create_chat_response = client.post("/messages/start", data={"username": "user2"})
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    message_payloads = [
        '{"msg":"first-from-user1"}',
        '{"msg":"second-from-user1"}',
        '{"msg":"third-from-user1"}',
    ]

    with client.websocket_connect(f"/ws/{chat_id}") as sender_ws:
        sender_status = receive_json_with_timeout(sender_ws)
        assert sender_status["type"] == "status"
        assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}

        for expected_id, payload in enumerate(message_payloads, start=1):
            sender_ws.send_text(payload)
            echoed_message = receive_until_type(sender_ws, "message")
            assert_message_payload_contains(echoed_message, {
                "type": "message",
                "message_id": expected_id,
                "reply_to_message_id": None,
                "sender": "user1",
                "sender_device_id": None,
                "content": payload,
                "historical": False,
                "delivery_status": "sent",
                "attachment": None,
                "deleted_for_all": False,
            })

    db_session = SessionLocal()
    try:
        saved_messages = db_session.query(Message).filter(Message.chat_id == chat_id).order_by(Message.id).all()
        assert [msg.content for msg in saved_messages] == message_payloads
        assert all(msg.delivered_at is None for msg in saved_messages)
        assert all(msg.read_at is None for msg in saved_messages)
    finally:
        db_session.close()

    with second_client.websocket_connect(f"/ws/{chat_id}") as reconnected_ws:
        reconnect_status = receive_json_with_timeout(reconnected_ws)
        assert reconnect_status["type"] == "status"

        history_messages = [
            receive_until_type(reconnected_ws, "message"),
            receive_until_type(reconnected_ws, "message"),
            receive_until_type(reconnected_ws, "message"),
        ]
        history_complete = receive_json_with_timeout(reconnected_ws)

    assert len(history_messages) == 3
    assert_message_payload_contains(history_messages[0], {
            "type": "message",
            "message_id": 1,
            "reply_to_message_id": None,
            "sender": "user1",
            "sender_device_id": None,
            "content": message_payloads[0],
            "historical": True,
            "delivery_status": "read",
            "attachment": None,
            "deleted_for_all": False,
        })
    assert_message_payload_contains(history_messages[1], {
            "type": "message",
            "message_id": 2,
            "reply_to_message_id": None,
            "sender": "user1",
            "sender_device_id": None,
            "content": message_payloads[1],
            "historical": True,
            "delivery_status": "read",
            "attachment": None,
            "deleted_for_all": False,
        })
    assert_message_payload_contains(history_messages[2], {
            "type": "message",
            "message_id": 3,
            "reply_to_message_id": None,
            "sender": "user1",
            "sender_device_id": None,
            "content": message_payloads[2],
            "historical": True,
            "delivery_status": "read",
            "attachment": None,
            "deleted_for_all": False,
        })
    assert history_complete == {"type": "history_complete"}


def test_websocket_media_message_persists_attachment(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_default_x3dh_bundle(second_client).status_code == 200

    create_chat_response = client.post("/messages/start", data={"username": "user2"})
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    media_payload = {
        "type": "media_message",
        "caption": "listen",
        "attachment": {
            "kind": "audio",
            "url": "/static/uploads/messages/test-track.mp3",
            "name": "track.mp3",
            "mime_type": "audio/mpeg",
            "size": 12345,
        },
    }

    with client.websocket_connect(f"/ws/{chat_id}") as sender_ws:
        sender_status = receive_json_with_timeout(sender_ws)
        assert sender_status["type"] == "status"
        assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}

        sender_ws.send_json(media_payload)
        echoed_message = receive_until_type(sender_ws, "message")

    assert_message_payload_contains(echoed_message, {
        "type": "message",
        "message_id": 1,
        "reply_to_message_id": None,
        "sender": "user1",
        "sender_device_id": None,
        "content": "listen",
        "historical": False,
        "delivery_status": "sent",
        "attachment": {
            "kind": "audio",
            "url": "/static/uploads/messages/test-track.mp3",
            "name": "track.mp3",
            "mime_type": "audio/mpeg",
            "size": 12345,
        },
        "deleted_for_all": False,
    })

    db_session = SessionLocal()
    try:
        saved_message = db_session.query(Message).filter(Message.chat_id == chat_id).one()
        assert saved_message.content == "listen"
        assert saved_message.attachment_kind == "audio"
        assert saved_message.attachment_url == "/static/uploads/messages/test-track.mp3"
        assert saved_message.attachment_name == "track.mp3"
        assert saved_message.attachment_mime_type == "audio/mpeg"
        assert saved_message.attachment_size == 12345
    finally:
        db_session.close()


def test_websocket_group_media_caption_uses_device_payloads(client, second_client):
    third_client = TestClient(client.app)
    third_client.get("/")
    third_headers = {"X-CSRF-Token": third_client.cookies.get("csrf_token", "")}

    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/register",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/login",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert upload_x3dh_keys(
        client,
        device_id="sender-device-1",
        device_name="Sender device",
        identity_key="public-key-user1",
        identity_signing_key="identity-signing-user1",
        signed_prekey="signed-prekey-user1",
        signed_prekey_signature="signed-prekey-signature-user1",
        signed_prekey_key_id=201,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        second_client,
        device_id="receiver-device-1",
        device_name="Receiver device 1",
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200
    assert third_client.post(
        "/users/x3dh-keys",
        json={
            "device_id": "receiver-device-2",
            "device_name": "Receiver device 2",
            "identity_key": "public-key-user3",
            "identity_signing_key": "identity-signing-user3",
            "signed_prekey": "signed-prekey-user3",
            "signed_prekey_signature": "signed-prekey-signature-user3",
            "signed_prekey_key_id": 301,
            "one_time_prekeys": [],
        },
        headers=third_headers,
    ).status_code == 200

    create_chat_response = client.post(
        "/messages/start-group",
        data={"title": "Core team", "usernames": '["user2","user3"]'},
    )
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    receiver_payload_1 = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":10,"counter":4,"distribution":{"epk":"r1","nonce":"n1","message":"m1"},"distribution_signature":"sig1","algorithm":"AES-GCM","iv":"iv1","ciphertext":"ct1"}'
    receiver_payload_2 = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":10,"counter":4,"distribution":{"epk":"r2","nonce":"n2","message":"m2"},"distribution_signature":"sig2","algorithm":"AES-GCM","iv":"iv2","ciphertext":"ct2"}'
    sender_payload = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":10,"counter":4,"distribution":{"epk":"s1","nonce":"sn1","message":"sm1"},"distribution_signature":"sig-self","algorithm":"AES-GCM","iv":"siv1","ciphertext":"sct1"}'
    media_payload = {
        "type": "media_message",
        "caption": {
            "version": 4,
            "device_payloads": {
                "receiver-device-1": receiver_payload_1,
                "receiver-device-2": receiver_payload_2,
            },
            "sender_device_payloads": {
                "sender-device-1": sender_payload,
            },
        },
        "attachment": {
            "kind": "image",
            "url": "/static/uploads/messages/group-image.bin",
            "name": "photo.bin",
            "mime_type": "application/octet-stream",
            "size": 512,
            "meta": {
                "encrypted": True,
                "chat_id": str(chat_id),
            },
        },
    }

    with client.websocket_connect(f"/ws/{chat_id}?device_id=sender-device-1") as sender_ws:
        assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}
        sender_ws.send_json(media_payload)
        sender_message = receive_until_type(sender_ws, "message")

    assert sender_message["content"] == sender_payload
    assert sender_message["attachment"]["url"] == "/static/uploads/messages/group-image.bin"

    with second_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-1") as receiver_ws:
        receiver_message = receive_until_type(receiver_ws, "message")
        receiver_complete = receive_json_with_timeout(receiver_ws)

    assert receiver_message["content"] == receiver_payload_1
    assert receiver_message["historical"] is True
    assert receiver_complete == {"type": "history_complete"}

    db_session = SessionLocal()
    try:
        saved_message = db_session.query(Message).filter(Message.chat_id == chat_id).one()
        assert saved_message.attachment_url == "/static/uploads/messages/group-image.bin"
        payload_rows = (
            db_session.query(MessageDevicePayload)
            .filter(MessageDevicePayload.message_id == saved_message.id)
            .all()
        )
        payloads_by_device = {row.device_id: row.payload for row in payload_rows}
        assert payloads_by_device["sender-device-1"] == sender_payload
        assert payloads_by_device["receiver-device-1"] == receiver_payload_1
        assert payloads_by_device["receiver-device-2"] == receiver_payload_2
    finally:
        db_session.close()


def test_websocket_reply_to_message_persists_reference(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_default_x3dh_bundle(second_client).status_code == 200

    create_chat_response = client.post("/messages/start", data={"username": "user2"})
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    first_payload = '{"version":2,"recipient":{"epk":"a1","nonce":"b1","message":"c1"},"sender":{"epk":"a2","nonce":"b2","message":"c2"}}'
    reply_payload = {
        "version": 2,
        "reply_to_message_id": 1,
        "recipient": {"epk": "r1", "nonce": "n1", "message": "m1"},
        "sender": {"epk": "r2", "nonce": "n2", "message": "m2"},
    }

    with client.websocket_connect(f"/ws/{chat_id}") as sender_ws:
        receive_json_with_timeout(sender_ws)
        receive_json_with_timeout(sender_ws)

        sender_ws.send_text(first_payload)
        first_message = receive_until_type(sender_ws, "message")
        assert first_message["reply_to_message_id"] is None

        sender_ws.send_json(reply_payload)
        replied_message = receive_until_type(sender_ws, "message")

    assert replied_message["message_id"] == 2
    assert replied_message["reply_to_message_id"] == 1

    db_session = SessionLocal()
    try:
        saved_reply = db_session.query(Message).filter(Message.id == 2).one()
        assert saved_reply.reply_to_message_id == 1
    finally:
        db_session.close()


def test_websocket_delete_for_self_hides_message_on_reconnect(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert upload_default_x3dh_bundle(second_client).status_code == 200

    create_chat_response = client.post("/messages/start", data={"username": "user2"})
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    with client.websocket_connect(f"/ws/{chat_id}") as sender_ws:
        receive_json_with_timeout(sender_ws)
        receive_json_with_timeout(sender_ws)
        sender_ws.send_text("delete-me")
        sent_message = receive_until_type(sender_ws, "message")

    delete_response = client.post(f"/messages/{sent_message['message_id']}/delete-self")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"status": "ok"}

    with client.websocket_connect(f"/ws/{chat_id}") as sender_reconnect_ws:
        receive_json_with_timeout(sender_reconnect_ws)
        history_complete = receive_json_with_timeout(sender_reconnect_ws)

    assert history_complete == {"type": "history_complete"}

    with second_client.websocket_connect(f"/ws/{chat_id}") as receiver_ws:
        receive_json_with_timeout(receiver_ws)
        receiver_message = receive_until_type(receiver_ws, "message")
        history_complete = receive_json_with_timeout(receiver_ws)

    assert receiver_message["content"] == "delete-me"
    assert receiver_message["historical"] is True
    assert history_complete == {"type": "history_complete"}


def test_websocket_device_specific_payload_delivery_and_history(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    assert upload_x3dh_keys(
        client,
        device_id="sender-device-1",
        device_name="Sender device",
        identity_key="public-key-user1",
        identity_signing_key="identity-signing-user1",
        signed_prekey="signed-prekey-user1",
        signed_prekey_signature="signed-prekey-signature-user1",
        signed_prekey_key_id=201,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        second_client,
        device_id="receiver-device-1",
        device_name="Receiver device",
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200

    create_chat_response = client.post("/messages/start", data={"username": "user2"})
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    recipient_payload = '{"version":3,"sender_copy":{"epk":"rcp","nonce":"n1","message":"m1"},"sender_state":null}'
    sender_payload = '{"version":3,"sender_copy":{"epk":"snd","nonce":"n2","message":"m2"},"sender_state":null}'
    fanout_payload = {
        "version": 4,
        "device_payloads": {
            "receiver-device-1": recipient_payload,
        },
        "sender_device_payloads": {
            "sender-device-1": sender_payload,
        },
    }

    with client.websocket_connect(f"/ws/{chat_id}?device_id=sender-device-1") as sender_ws:
        sender_status = receive_json_with_timeout(sender_ws)
        assert sender_status["type"] == "status"
        assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}

        sender_ws.send_json(fanout_payload)
        sender_message = receive_until_type(sender_ws, "message")

    assert sender_message["content"] == sender_payload
    assert sender_message["sender_device_id"] == "sender-device-1"
    assert sender_message["historical"] is False

    with second_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-1") as history_ws:
        history_status = receive_json_with_timeout(history_ws)
        history_message = receive_until_type(history_ws, "message")
        history_complete = receive_json_with_timeout(history_ws)

    assert history_status["type"] == "status"
    assert history_message["content"] == recipient_payload
    assert history_message["sender_device_id"] == "sender-device-1"
    assert history_message["historical"] is True
    assert history_complete == {"type": "history_complete"}


def test_websocket_group_chat_device_fanout(client, second_client):
    third_client = TestClient(client.app)
    third_client.get("/")
    third_headers = {"X-CSRF-Token": third_client.cookies.get("csrf_token", "")}

    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/register",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/login",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert upload_x3dh_keys(
        client,
        device_id="sender-device-1",
        device_name="Sender device",
        identity_key="public-key-user1",
        identity_signing_key="identity-signing-user1",
        signed_prekey="signed-prekey-user1",
        signed_prekey_signature="signed-prekey-signature-user1",
        signed_prekey_key_id=201,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        second_client,
        device_id="receiver-device-1",
        device_name="Receiver device 1",
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200
    assert third_client.post(
        "/users/x3dh-keys",
        json={
            "device_id": "receiver-device-2",
            "device_name": "Receiver device 2",
            "identity_key": "public-key-user3",
            "identity_signing_key": "identity-signing-user3",
            "signed_prekey": "signed-prekey-user3",
            "signed_prekey_signature": "signed-prekey-signature-user3",
            "signed_prekey_key_id": 301,
            "one_time_prekeys": [],
        },
        headers=third_headers,
    ).status_code == 200

    create_chat_response = client.post(
        "/messages/start-group",
        data={"title": "Core team", "usernames": '["user2","user3"]'},
    )
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    receiver_payload_1 = '{"version":3,"sender_copy":{"epk":"g1","nonce":"n1","message":"m1"},"sender_state":null}'
    receiver_payload_2 = '{"version":3,"sender_copy":{"epk":"g2","nonce":"n2","message":"m2"},"sender_state":null}'
    sender_payload = '{"version":3,"sender_copy":{"epk":"sg","nonce":"sn","message":"sm"},"sender_state":null}'
    fanout_payload = {
        "version": 4,
        "device_payloads": {
            "receiver-device-1": receiver_payload_1,
            "receiver-device-2": receiver_payload_2,
        },
        "sender_device_payloads": {
            "sender-device-1": sender_payload,
        },
    }

    with client.websocket_connect(f"/ws/{chat_id}?device_id=sender-device-1") as sender_ws:
        assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}

        sender_ws.send_json(fanout_payload)

        sender_message = receive_until_type(sender_ws, "message")

    assert sender_message["content"] == sender_payload
    assert sender_message["sender_device_id"] == "sender-device-1"
    assert sender_message["historical"] is False

    with second_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-1") as receiver_ws_1:
        receiver_message_1 = receive_until_type(receiver_ws_1, "message")
        receiver_1_complete = receive_json_with_timeout(receiver_ws_1)

    assert receiver_message_1["content"] == receiver_payload_1
    assert receiver_message_1["sender_device_id"] == "sender-device-1"
    assert receiver_message_1["historical"] is True
    assert receiver_1_complete == {"type": "history_complete"}

    with third_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-2") as receiver_ws_2:
        receiver_message_2 = receive_until_type(receiver_ws_2, "message")
        history_complete = receive_json_with_timeout(receiver_ws_2)

    assert receiver_message_2["content"] == receiver_payload_2
    assert receiver_message_2["sender_device_id"] == "sender-device-1"
    assert receiver_message_2["historical"] is True
    assert history_complete == {"type": "history_complete"}


def test_websocket_group_chat_multidevice_history_sync(client, second_client):
    third_client = TestClient(client.app)
    third_client.get("/")
    third_headers = {"X-CSRF-Token": third_client.cookies.get("csrf_token", "")}

    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/register",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/login",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert upload_x3dh_keys(
        client,
        device_id="sender-device-1",
        device_name="Sender device 1",
        identity_key="public-key-user1",
        identity_signing_key="identity-signing-user1",
        signed_prekey="signed-prekey-user1",
        signed_prekey_signature="signed-prekey-signature-user1",
        signed_prekey_key_id=201,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        client,
        device_id="sender-device-2",
        device_name="Sender device 2",
        identity_key="public-key-user1-device-2",
        identity_signing_key="identity-signing-user1-device-2",
        signed_prekey="signed-prekey-user1-device-2",
        signed_prekey_signature="signed-prekey-signature-user1-device-2",
        signed_prekey_key_id=202,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        second_client,
        device_id="receiver-device-1",
        device_name="Receiver device 1",
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200
    assert third_client.post(
        "/users/x3dh-keys",
        json={
            "device_id": "receiver-device-2",
            "device_name": "Receiver device 2",
            "identity_key": "public-key-user3",
            "identity_signing_key": "identity-signing-user3",
            "signed_prekey": "signed-prekey-user3",
            "signed_prekey_signature": "signed-prekey-signature-user3",
            "signed_prekey_key_id": 301,
            "one_time_prekeys": [],
        },
        headers=third_headers,
    ).status_code == 200

    create_chat_response = client.post(
        "/messages/start-group",
        data={"title": "Core team", "usernames": '["user2","user3"]'},
    )
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    receiver_payload_1 = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":5,"counter":1,"distribution":{"epk":"g1","nonce":"n1","message":"m1"},"distribution_signature":"sig1","algorithm":"AES-GCM","iv":"iv1","ciphertext":"ct1"}'
    receiver_payload_2 = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":5,"counter":1,"distribution":{"epk":"g2","nonce":"n2","message":"m2"},"distribution_signature":"sig2","algorithm":"AES-GCM","iv":"iv2","ciphertext":"ct2"}'
    sender_payload_1 = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":5,"counter":1,"distribution":{"epk":"gs1","nonce":"sn1","message":"sm1"},"distribution_signature":"sig-self-1","algorithm":"AES-GCM","iv":"siv1","ciphertext":"sct1"}'
    sender_payload_2 = '{"version":5,"mode":"group_sender_key","sender_device_id":"sender-device-1","sender_key_id":5,"counter":1,"distribution":{"epk":"gs2","nonce":"sn2","message":"sm2"},"distribution_signature":"sig-self-2","algorithm":"AES-GCM","iv":"siv2","ciphertext":"sct2"}'
    fanout_payload = {
        "version": 4,
        "device_payloads": {
            "receiver-device-1": receiver_payload_1,
            "receiver-device-2": receiver_payload_2,
        },
        "sender_device_payloads": {
            "sender-device-1": sender_payload_1,
            "sender-device-2": sender_payload_2,
        },
    }

    with client.websocket_connect(f"/ws/{chat_id}?device_id=sender-device-1") as sender_ws:
        assert receive_json_with_timeout(sender_ws) == {"type": "history_complete"}

        sender_ws.send_json(fanout_payload)

        sender_message = receive_until_type(sender_ws, "message")

    assert sender_message["content"] == sender_payload_1
    assert sender_message["sender_device_id"] == "sender-device-1"
    assert sender_message["historical"] is False

    with second_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-1") as receiver_ws:
        receiver_message = receive_until_type(receiver_ws, "message")
        receiver_complete = receive_json_with_timeout(receiver_ws)

    assert receiver_message["content"] == receiver_payload_1
    assert receiver_message["sender_device_id"] == "sender-device-1"
    assert receiver_message["historical"] is True
    assert receiver_complete == {"type": "history_complete"}

    with client.websocket_connect(f"/ws/{chat_id}?device_id=sender-device-2") as sender_device_2_ws:
        sender_device_2_message = receive_until_type(sender_device_2_ws, "message")
        sender_device_2_complete = receive_json_with_timeout(sender_device_2_ws)

    assert sender_device_2_message["content"] == sender_payload_2
    assert sender_device_2_message["sender_device_id"] == "sender-device-1"
    assert sender_device_2_message["historical"] is True
    assert sender_device_2_complete == {"type": "history_complete"}

    with third_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-2") as receiver_device_2_ws:
        receiver_device_2_message = receive_until_type(receiver_device_2_ws, "message")
        receiver_device_2_complete = receive_json_with_timeout(receiver_device_2_ws)

    assert receiver_device_2_message["content"] == receiver_payload_2
    assert receiver_device_2_message["sender_device_id"] == "sender-device-1"
    assert receiver_device_2_message["historical"] is True
    assert receiver_device_2_complete == {"type": "history_complete"}


def test_removed_group_participant_loses_open_websocket_access(client, second_client):
    third_client = TestClient(client.app)
    third_client.get("/")
    third_headers = {"X-CSRF-Token": third_client.cookies.get("csrf_token", "")}

    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/register",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303
    assert third_client.post(
        "/login",
        data={"email": "user3@example.com", "password": "Password123!"},
        headers=third_headers,
        follow_redirects=False,
    ).status_code == 303

    assert upload_x3dh_keys(
        client,
        device_id="creator-device-1",
        device_name="Creator device",
        identity_key="public-key-user1",
        identity_signing_key="identity-signing-user1",
        signed_prekey="signed-prekey-user1",
        signed_prekey_signature="signed-prekey-signature-user1",
        signed_prekey_key_id=201,
        one_time_prekeys=[],
    ).status_code == 200
    assert upload_x3dh_keys(
        second_client,
        device_id="member-device-1",
        device_name="Member device",
        identity_key="public-key-user2",
        identity_signing_key="identity-signing-user2",
        signed_prekey="signed-prekey-user2",
        signed_prekey_signature="signed-prekey-signature-user2",
        signed_prekey_key_id=101,
        one_time_prekeys=[],
    ).status_code == 200
    assert third_client.post(
        "/users/x3dh-keys",
        json={
            "device_id": "removed-device-1",
            "device_name": "Removed device",
            "identity_key": "public-key-user3",
            "identity_signing_key": "identity-signing-user3",
            "signed_prekey": "signed-prekey-user3",
            "signed_prekey_signature": "signed-prekey-signature-user3",
            "signed_prekey_key_id": 301,
            "one_time_prekeys": [],
        },
        headers=third_headers,
    ).status_code == 200

    create_chat_response = client.post(
        "/messages/start-group",
        data={"title": "Core team", "usernames": '["user2","user3"]'},
    )
    assert create_chat_response.status_code == 200
    chat_id = create_chat_response.json()["chat_id"]

    creator_payload = '{"version":5,"mode":"group_sender_key","sender_device_id":"creator-device-1","sender_key_id":1,"counter":0,"distribution":{"epk":"a","nonce":"b","message":"c"},"distribution_signature":"sig","algorithm":"AES-GCM","iv":"iv","ciphertext":"ct"}'

    with client.websocket_connect(f"/ws/{chat_id}?device_id=creator-device-1") as creator_ws:
        assert receive_json_with_timeout(creator_ws) == {"type": "history_complete"}

        with third_client.websocket_connect(f"/ws/{chat_id}?device_id=removed-device-1") as removed_ws:
            assert receive_json_with_timeout(removed_ws) == {"type": "history_complete"}

            remove_response = client.delete(
                f"/chats/{chat_id}/participants/3",
                headers={"X-CSRF-Token": client.cookies.get("csrf_token", "")},
            )
            assert remove_response.status_code == 200

            removed_event = receive_until_type(removed_ws, "chat_deleted")
            assert removed_event == {"type": "chat_deleted", "chat_id": chat_id, "delete_for_all": False}

            creator_ws.send_text(creator_payload)
            creator_message = receive_until_type(creator_ws, "message")
            assert creator_message["message_id"] == 1
            assert creator_message["sender_device_id"] == "creator-device-1"

            with pytest.raises(Exception):
                removed_ws.send_text(creator_payload)
                receive_json_with_timeout(removed_ws)
