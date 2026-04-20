from tests.helpers import login_user, register_user, upload_public_key


def test_auth_flow_and_profile_endpoints(client):
    response = client.get("/")
    assert response.status_code == 200

    response = client.get("/register")
    assert response.status_code == 200

    response = client.get("/login")
    assert response.status_code == 200

    response = register_user(client, "user1@example.com")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    response = login_user(client, "user1@example.com")
    assert response.status_code == 303
    assert response.headers["location"] == "/profile"
    assert "access_token" in client.cookies
    assert "refresh_token" in client.cookies

    response = client.get("/users/me")
    assert response.status_code == 200
    assert response.json()["username"] == "user1"

    response = upload_public_key(client, "public-key-user1")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    response = client.get("/profile")
    assert response.status_code == 200
    assert "user1@example.com" in response.text

    response = client.post("/profile", data={"name": "alice"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/profile"

    response = client.get("/users/me")
    assert response.status_code == 200
    assert response.json()["username"] == "alice"

    old_refresh = client.cookies.get("refresh_token")
    response = client.post("/refresh", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/profile"
    assert client.cookies.get("refresh_token") == old_refresh

    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_refresh_json_response_and_security_headers(client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert login_user(client, "user1@example.com").status_code == 303

    old_refresh = client.cookies.get("refresh_token")
    response = client.post(
        "/refresh",
        headers={
            "X-Requested-With": "fetch",
            "Accept": "application/json",
        },
        follow_redirects=False,
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert client.cookies.get("refresh_token") == old_refresh
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "camera=()" in response.headers["Permissions-Policy"]


def test_logout_revokes_session_for_protected_routes(client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert login_user(client, "user1@example.com").status_code == 303

    response = client.get("/users/me")
    assert response.status_code == 200

    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    response = client.get("/users/me")
    assert response.status_code == 401

    response = client.post(
        "/refresh",
        headers={
            "X-Requested-With": "fetch",
            "Accept": "application/json",
        },
        follow_redirects=False,
    )
    assert response.status_code == 401
