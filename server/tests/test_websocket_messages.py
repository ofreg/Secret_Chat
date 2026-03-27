from app.db.models import Message
from tests.helpers import login_user, register_user


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

            with second_client.websocket_connect(f"/ws/{chat_id}") as receiver_ws:
                receiver_status = receiver_ws.receive_json()
                assert receiver_status["type"] == "status"

                sender_ws.send_text(message_payload)

                sender_message = sender_ws.receive_json()
                receiver_message = receiver_ws.receive_json()
                first_notification = user_ws.receive_json()
                second_notification = user_ws.receive_json()

    assert sender_message == {
        "type": "message",
        "sender": "user1",
        "content": message_payload,
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

    assert history_status["type"] == "status"
    assert history_message == {
        "type": "message",
        "sender": "user1",
        "content": message_payload,
    }
