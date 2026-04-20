import pytest

from app.db.models import Message
from tests.helpers import login_user, register_user


def test_websocket_routes_require_valid_session(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/user"):
            assert False, "Anonymous websocket connection should not stay open"

    with pytest.raises(Exception):
        with client.websocket_connect("/ws/1"):
            assert False, "Anonymous chat websocket connection should not stay open"


def test_websocket_chat_delivery_and_message_persistence(client, second_client, db_session):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

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

                sender_message = sender_ws.receive_json()
                receiver_message = receiver_ws.receive_json()
                first_notification = user_ws.receive_json()
                second_notification = user_ws.receive_json()

    assert sender_message == {
        "type": "message",
        "message_id": 1,
        "sender": "user1",
        "content": message_payload,
        "historical": False,
    }
    assert receiver_message == sender_message
    assert first_notification == {"type": "new_chat"}
    assert second_notification == {"type": "new_message", "chat_id": chat_id}

    saved_message = db_session.query(Message).filter(Message.chat_id == chat_id).one()
    assert saved_message.sender_id == 1
    assert saved_message.content == message_payload

    with second_client.websocket_connect(f"/ws/{chat_id}") as history_ws:
        history_status = history_ws.receive_json()
        history_message = history_ws.receive_json()
        history_complete = history_ws.receive_json()

    assert history_status["type"] == "status"
    assert history_message == {
        "type": "message",
        "message_id": 1,
        "sender": "user1",
        "content": message_payload,
        "historical": True,
    }
    assert history_complete == {"type": "history_complete"}


def test_websocket_chat_history_reconnect_preserves_order(client, second_client, db_session):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

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
            echoed_message = sender_ws.receive_json()
            assert echoed_message == {
                "type": "message",
                "message_id": expected_id,
                "sender": "user1",
                "content": payload,
                "historical": False,
            }

    saved_messages = db_session.query(Message).filter(Message.chat_id == chat_id).order_by(Message.id).all()
    assert [msg.content for msg in saved_messages] == message_payloads

    with second_client.websocket_connect(f"/ws/{chat_id}") as reconnected_ws:
        reconnect_status = reconnected_ws.receive_json()
        assert reconnect_status["type"] == "status"

        history_messages = [
            reconnected_ws.receive_json(),
            reconnected_ws.receive_json(),
            reconnected_ws.receive_json(),
        ]
        history_complete = reconnected_ws.receive_json()

    assert history_messages == [
        {
            "type": "message",
            "message_id": 1,
            "sender": "user1",
            "content": message_payloads[0],
            "historical": True,
        },
        {
            "type": "message",
            "message_id": 2,
            "sender": "user1",
            "content": message_payloads[1],
            "historical": True,
        },
        {
            "type": "message",
            "message_id": 3,
            "sender": "user1",
            "content": message_payloads[2],
            "historical": True,
        },
    ]
    assert history_complete == {"type": "history_complete"}
