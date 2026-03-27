from fastapi.testclient import TestClient


def register_user(test_client: TestClient, email: str, password: str = "Password123!"):
    return test_client.post(
        "/register",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


def login_user(test_client: TestClient, email: str, password: str = "Password123!"):
    return test_client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


def upload_public_key(test_client: TestClient, public_key: str):
    return test_client.post("/users/keys", json={"public_key": public_key})
