import pytest

from app.db.models import Message
from app.db.session import SessionLocal
from tests.helpers import login_user, register_user, upload_x3dh_keys


def receive_until_type(websocket, expected_type: str):
    while True:
        payload = websocket.receive_json()
        if payload.get("type") == expected_type:
            return payload


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
            sender_status = sender_ws.receive_json()
            assert sender_status["type"] == "status"
            assert sender_status["is_online"] is True
            assert sender_ws.receive_json() == {"type": "history_complete"}

            with second_client.websocket_connect(f"/ws/{chat_id}") as receiver_ws:
                receiver_status = receiver_ws.receive_json()
                assert receiver_status["type"] == "status"
                assert receiver_ws.receive_json() == {"type": "history_complete"}

                sender_ws.send_text(message_payload)

                sender_message = receive_until_type(sender_ws, "message")
                receiver_message = receive_until_type(receiver_ws, "message")
                first_notification = user_ws.receive_json()

    assert sender_message == {
        "type": "message",
        "message_id": 1,
        "sender": "user1",
        "sender_device_id": None,
        "content": message_payload,
        "historical": False,
        "delivery_status": "read",
        "attachment": None,
        "deleted_for_all": False,
    }
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
        history_status = history_ws.receive_json()
        history_message = receive_until_type(history_ws, "message")
        history_complete = history_ws.receive_json()

    assert history_status["type"] == "status"
    assert history_message == {
        "type": "message",
        "message_id": 1,
        "sender": "user1",
        "sender_device_id": None,
        "content": message_payload,
        "historical": True,
        "delivery_status": "read",
        "attachment": None,
        "deleted_for_all": False,
    }
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
        sender_status = sender_ws.receive_json()
        assert sender_status["type"] == "status"
        assert sender_ws.receive_json() == {"type": "history_complete"}

        for expected_id, payload in enumerate(message_payloads, start=1):
            sender_ws.send_text(payload)
            echoed_message = receive_until_type(sender_ws, "message")
            assert echoed_message == {
                "type": "message",
                "message_id": expected_id,
                "sender": "user1",
                "sender_device_id": None,
                "content": payload,
                "historical": False,
                "delivery_status": "sent",
                "attachment": None,
                "deleted_for_all": False,
            }

    db_session = SessionLocal()
    try:
        saved_messages = db_session.query(Message).filter(Message.chat_id == chat_id).order_by(Message.id).all()
        assert [msg.content for msg in saved_messages] == message_payloads
        assert all(msg.delivered_at is None for msg in saved_messages)
        assert all(msg.read_at is None for msg in saved_messages)
    finally:
        db_session.close()

    with second_client.websocket_connect(f"/ws/{chat_id}") as reconnected_ws:
        reconnect_status = reconnected_ws.receive_json()
        assert reconnect_status["type"] == "status"

        history_messages = [
            receive_until_type(reconnected_ws, "message"),
            receive_until_type(reconnected_ws, "message"),
            receive_until_type(reconnected_ws, "message"),
        ]
        history_complete = reconnected_ws.receive_json()

    assert history_messages == [
        {
            "type": "message",
            "message_id": 1,
            "sender": "user1",
            "sender_device_id": None,
            "content": message_payloads[0],
            "historical": True,
            "delivery_status": "read",
            "attachment": None,
            "deleted_for_all": False,
        },
        {
            "type": "message",
            "message_id": 2,
            "sender": "user1",
            "sender_device_id": None,
            "content": message_payloads[1],
            "historical": True,
            "delivery_status": "read",
            "attachment": None,
            "deleted_for_all": False,
        },
        {
            "type": "message",
            "message_id": 3,
            "sender": "user1",
            "sender_device_id": None,
            "content": message_payloads[2],
            "historical": True,
            "delivery_status": "read",
            "attachment": None,
            "deleted_for_all": False,
        },
    ]
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
        sender_status = sender_ws.receive_json()
        assert sender_status["type"] == "status"
        assert sender_ws.receive_json() == {"type": "history_complete"}

        sender_ws.send_json(media_payload)
        echoed_message = receive_until_type(sender_ws, "message")

    assert echoed_message == {
        "type": "message",
        "message_id": 1,
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
    }

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
        sender_ws.receive_json()
        sender_ws.receive_json()
        sender_ws.send_text("delete-me")
        sent_message = receive_until_type(sender_ws, "message")

    delete_response = client.post(f"/messages/{sent_message['message_id']}/delete-self")
    assert delete_response.status_code == 200
    assert delete_response.json() == {"status": "ok"}

    with client.websocket_connect(f"/ws/{chat_id}") as sender_reconnect_ws:
        sender_reconnect_ws.receive_json()
        history_complete = sender_reconnect_ws.receive_json()

    assert history_complete == {"type": "history_complete"}

    with second_client.websocket_connect(f"/ws/{chat_id}") as receiver_ws:
        receiver_ws.receive_json()
        receiver_message = receive_until_type(receiver_ws, "message")
        history_complete = receiver_ws.receive_json()

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
        sender_status = sender_ws.receive_json()
        assert sender_status["type"] == "status"
        assert sender_ws.receive_json() == {"type": "history_complete"}

        with second_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-1") as receiver_ws:
            receiver_status = receiver_ws.receive_json()
            assert receiver_status["type"] == "status"
            assert receiver_ws.receive_json() == {"type": "history_complete"}

            sender_ws.send_json(fanout_payload)

            sender_message = receive_until_type(sender_ws, "message")
            receiver_message = receive_until_type(receiver_ws, "message")

    assert sender_message["content"] == sender_payload
    assert sender_message["sender_device_id"] == "sender-device-1"
    assert sender_message["historical"] is False
    assert receiver_message["content"] == recipient_payload
    assert receiver_message["sender_device_id"] == "sender-device-1"
    assert receiver_message["historical"] is False

    with second_client.websocket_connect(f"/ws/{chat_id}?device_id=receiver-device-1") as history_ws:
        history_status = history_ws.receive_json()
        history_message = receive_until_type(history_ws, "message")
        history_complete = history_ws.receive_json()

    assert history_status["type"] == "status"
    assert history_message["content"] == recipient_payload
    assert history_message["sender_device_id"] == "sender-device-1"
    assert history_message["historical"] is True
    assert history_complete == {"type": "history_complete"}
