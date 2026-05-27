import asyncio
import os
import sys
import time
from pathlib import Path
from contextlib import suppress

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import close_all_sessions


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SERVER_ROOT = PROJECT_ROOT / "server"
CLIENT_ROOT = PROJECT_ROOT / "client"
TEST_DB_PATH = SERVER_ROOT / "test_app.db"

os.environ.setdefault("DATABASE_URL_SYNC", f"sqlite:///{TEST_DB_PATH.as_posix()}")
os.environ.setdefault("DATABASE_URL_ASYNC", f"sqlite+aiosqlite:///{TEST_DB_PATH.as_posix()}")
os.environ.setdefault("JWT_SECRET_KEY", "12345678901234567890123456789012")
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("AVATAR_UPLOAD_DIR", str(CLIENT_ROOT / "static" / "uploads" / "avatars"))
os.environ.setdefault("MAX_AVATAR_SIZE_BYTES", str(2 * 1024 * 1024))
os.environ.setdefault("TEMPLATES_DIR", str(CLIENT_ROOT / "templates"))
os.environ.setdefault("STATIC_DIR", str(CLIENT_ROOT / "static"))

if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))

from app.core.rate_limit import forgot_password_attempts, login_attempts
from app.db.base import Base
from app.db.session import SessionLocal, async_engine, engine
from app.main import app
from app.utils.websocket_manager import manager


def prepare_csrf_client(test_client: TestClient) -> TestClient:
    original_post = test_client.post
    test_client.get("/")

    def csrf_post(*args, **kwargs):
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.setdefault("X-CSRF-Token", test_client.cookies.get("csrf_token", ""))
        return original_post(*args, headers=headers, **kwargs)

    test_client.post = csrf_post
    return test_client


def dispose_test_database_connections():
    with suppress(Exception):
        close_all_sessions()
    with suppress(Exception):
        engine.dispose()
    with suppress(Exception):
        asyncio.run(async_engine.dispose())


def reset_test_database_state():
    last_error = None
    for _attempt in range(5):
        try:
            dispose_test_database_connections()
            Base.metadata.drop_all(bind=engine)
            Base.metadata.create_all(bind=engine)
            return
        except OperationalError as error:
            last_error = error
            time.sleep(0.2)
    if last_error is not None:
        raise last_error


@pytest.fixture(autouse=True)
def reset_state():
    reset_test_database_state()

    login_attempts.clear()
    forgot_password_attempts.clear()
    manager.chat_connections.clear()
    manager.chat_user_connections.clear()
    manager.user_connections.clear()
    manager.online_users.clear()

    yield

    dispose_test_database_connections()
    manager.chat_connections.clear()
    manager.chat_user_connections.clear()
    manager.user_connections.clear()
    manager.online_users.clear()
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield prepare_csrf_client(test_client)


@pytest.fixture
def second_client():
    with TestClient(app) as test_client:
        yield prepare_csrf_client(test_client)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
