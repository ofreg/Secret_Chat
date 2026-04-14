from tests.helpers import login_user, register_user, upload_public_key, upload_x3dh_keys


def test_messages_endpoints_and_chat_bootstrap(client, second_client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert register_user(second_client, "user2@example.com").status_code == 303

    assert login_user(client, "user1@example.com").status_code == 303
    assert login_user(second_client, "user2@example.com").status_code == 303

    assert upload_public_key(client, "public-key-user1").status_code == 200
    assert upload_public_key(second_client, "public-key-user2").status_code == 200
    assert upload_x3dh_keys(
        second_client,
        public_key="public-key-user2",
        identity_key="identity-user2",
        signing_key="signing-user2",
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
    assert payload["public_key"] == "public-key-user2"
    assert payload["username"] == "user2"
    assert payload["avatar_url"] is None
    assert payload["avatar_class"].startswith("avatar-gradient-")
    assert payload["avatar_initial"] == "U"
    assert payload["prekey_bundle"] == {
        "identity_key": "identity-user2",
        "signing_key": "signing-user2",
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
        "identity_key": "identity-user2",
        "signing_key": "signing-user2",
        "signed_prekey": "signed-prekey-user2",
        "signed_prekey_signature": "signed-prekey-signature-user2",
        "signed_prekey_key_id": 101,
        "one_time_prekey": {"key_id": 1002, "public_key": "otpk-user2-2"},
    }

    response = client.get("/messages/get_keys", params={"chat_id": 1})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["public_key"] == "public-key-user2"
    assert payload["username"] == "user2"
    assert payload["avatar_url"] is None
    assert payload["avatar_class"].startswith("avatar-gradient-")
    assert payload["avatar_initial"] == "U"
    assert payload["prekey_bundle"] == {
        "identity_key": "identity-user2",
        "signing_key": "signing-user2",
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
            "identity_key": "identity-user2",
            "signing_key": "signing-user2",
            "signed_prekey": "signed-prekey-user2",
            "signed_prekey_signature": "signed-prekey-signature-user2",
            "signed_prekey_key_id": 101,
            "one_time_prekey": {"key_id": 1002, "public_key": "otpk-user2-2"},
        },
    }

    response = client.get("/users/prekey-bundle", params={"username": "user2"})
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "username": "user2",
        "bundle": {
            "identity_key": "identity-user2",
            "signing_key": "signing-user2",
            "signed_prekey": "signed-prekey-user2",
            "signed_prekey_signature": "signed-prekey-signature-user2",
            "signed_prekey_key_id": 101,
            "one_time_prekey": None,
        },
    }

    assert upload_x3dh_keys(
        second_client,
        public_key="public-key-user2",
        identity_key="identity-user2",
        signing_key="signing-user2",
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
            "identity_key": "identity-user2",
            "signing_key": "signing-user2",
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
