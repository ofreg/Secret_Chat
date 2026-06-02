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

def upload_x3dh_keys(
    test_client: TestClient,
    *,
    device_id: str | None = None,
    device_name: str | None = None,
    identity_key: str,
    identity_signing_key: str,
    signed_prekey: str,
    signed_prekey_signature: str,
    signed_prekey_key_id: int,
    one_time_prekeys: list[dict],
):
    return test_client.post(
        "/users/x3dh-keys",
        json={
            "device_id": device_id,
            "device_name": device_name,
            "identity_key": identity_key,
            "identity_signing_key": identity_signing_key,
            "signed_prekey": signed_prekey,
            "signed_prekey_signature": signed_prekey_signature,
            "signed_prekey_key_id": signed_prekey_key_id,
            "one_time_prekeys": one_time_prekeys,
        },
    )
