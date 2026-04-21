import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


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
from app.db.session import SessionLocal, engine
from app.main import app
from app.utils.websocket_manager import manager


@pytest.fixture(autouse=True)
def reset_state():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    login_attempts.clear()
    forgot_password_attempts.clear()
    manager.chat_connections.clear()
    manager.user_connections.clear()
    manager.online_users.clear()

    yield

    manager.chat_connections.clear()
    manager.user_connections.clear()
    manager.online_users.clear()
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def second_client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
