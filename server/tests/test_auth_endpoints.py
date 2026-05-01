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


def test_password_reset_flow(client, monkeypatch):
    sent_links = []

    def fake_send_password_reset_email(to_email: str, reset_link: str):
        sent_links.append((to_email, reset_link))

    monkeypatch.setattr("app.routers.auth.is_mail_configured", lambda: True)
    monkeypatch.setattr("app.routers.auth.send_password_reset_email", fake_send_password_reset_email)

    assert register_user(client, "user1@example.com").status_code == 303

    response = client.get("/forgot-password")
    assert response.status_code == 200

    response = client.post("/forgot-password", data={"email": "user1@example.com"})
    assert response.status_code == 200
    assert sent_links
    assert sent_links[0][0] == "user1@example.com"
    assert "/reset-password?token=" in sent_links[0][1]

    token = sent_links[0][1].split("token=", 1)[1]

    response = client.get("/reset-password", params={"token": token})
    assert response.status_code == 200

    response = client.post(
        "/reset-password",
        data={
            "token": token,
            "password": "NewPassword123!",
            "confirm_password": "NewPassword123!",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"

    failed_login = login_user(client, "user1@example.com", password="Password123!")
    assert failed_login.status_code == 400

    success_login = login_user(client, "user1@example.com", password="NewPassword123!")
    assert success_login.status_code == 303
    assert success_login.headers["location"] == "/profile"

    reused_token_response = client.post(
        "/reset-password",
        data={
            "token": token,
            "password": "AnotherPassword123!",
            "confirm_password": "AnotherPassword123!",
        },
    )
    assert reused_token_response.status_code == 400
    assert "invalid or expired" in reused_token_response.text


def test_forgot_password_rate_limit(client, monkeypatch):
    monkeypatch.setattr("app.routers.auth.is_mail_configured", lambda: True)
    monkeypatch.setattr("app.routers.auth.send_password_reset_email", lambda *_args, **_kwargs: None)

    for _ in range(5):
        response = client.post("/forgot-password", data={"email": "user1@example.com"})
        assert response.status_code == 200

    response = client.post("/forgot-password", data={"email": "user1@example.com"})
    assert response.status_code == 429


def test_change_email_rotates_current_session_to_new_identity(client):
    assert register_user(client, "user1@example.com").status_code == 303
    assert login_user(client, "user1@example.com").status_code == 303

    response = client.post(
        "/profile",
        data={
            "action": "change_email",
            "email": "updated_user1@example.com",
            "current_password": "Password123!",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/profile"

    response = client.get("/users/me")
    assert response.status_code == 200
    assert response.json()["email"] == "updated_user1@example.com"

    response = client.get("/profile")
    assert response.status_code == 200
    assert "updated_user1@example.com" in response.text

    response = client.post("/logout", follow_redirects=False)
    assert response.status_code == 303

    old_email_login = login_user(client, "user1@example.com")
    assert old_email_login.status_code == 400

    new_email_login = login_user(client, "updated_user1@example.com")
    assert new_email_login.status_code == 303
    assert new_email_login.headers["location"] == "/profile"
