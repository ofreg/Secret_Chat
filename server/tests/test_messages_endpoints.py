from tests.helpers import login_user, register_user, upload_public_key


def test_messages_endpoints_and_chat_bootstrap(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    assert upload_public_key(client, "public-key-user1").status_code == 200
    assert upload_public_key(second_client, "public-key-user2").status_code == 200

    response = client.get("/messages/search", params={"query": "user2"})
    assert response.status_code == 200
    assert response.json() == [{"id": 2, "username": "user2"}]

    response = client.post("/messages/start", data={"username": "user2"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["chat_id"] == 1
    assert payload["public_key"] == "public-key-user2"
    assert payload["username"] == "user2"

    response = client.get("/messages/get_keys", params={"chat_id": 1})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["public_key"] == "public-key-user2"
    assert payload["username"] == "user2"

    response = client.get("/messages", params={"chat_id": 1})
    assert response.status_code == 200
    assert "/static/js/messages.js" in response.text
    assert "public-key-user2" in response.text
