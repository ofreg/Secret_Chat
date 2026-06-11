from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from collections import defaultdict
from time import time
import os
import logging
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.routers import auth, messages
from app.db.base import Base
from app.db.session import engine
from sqlalchemy import inspect, text
from sqlalchemy.exc import OperationalError
from fastapi.staticfiles import StaticFiles
from app.utils.csrf import attach_csrf_cookie, configure_templates, get_or_create_csrf_token
from app.utils.logging_config import setup_logging
# ---------------------- Конфіг ----------------------
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60

# Абсолютний шлях всередині контейнера
templates = configure_templates(Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates")))
setup_logging()
logger = logging.getLogger("app.main")

# ---------------------- FastAPI ----------------------
app = FastAPI()
app.mount(
    "/static",
    StaticFiles(directory=os.getenv("STATIC_DIR", "/code/client/static")),
    name="static"
)


def wants_html_response(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept or "*/*" in accept


@app.exception_handler(StarletteHTTPException)
async def handle_http_exception(request: Request, exc: StarletteHTTPException):
    if exc.status_code >= 500:
        logger.error("HTTP error %s on %s %s", exc.status_code, request.method, request.url.path)
    elif exc.status_code in {403, 404}:
        logger.warning("HTTP %s on %s %s", exc.status_code, request.method, request.url.path)

    if exc.status_code == 401 and "text/html" in request.headers.get("accept", ""):
        return RedirectResponse("/login?reauth=1", status_code=303)

    if exc.status_code in {403, 404} and wants_html_response(request):
        return templates.TemplateResponse(
            request,
            f"{exc.status_code}.html",
            {"request": request},
            status_code=exc.status_code,
        )

    if "application/json" in request.headers.get("accept", ""):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    return PlainTextResponse(str(exc.detail), status_code=exc.status_code)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    started_at = time()
    get_or_create_csrf_token(request)
    try:
        response = await call_next(request)
    except Exception:
        duration_ms = round((time() - started_at) * 1000, 2)
        logger.exception(
            "Unhandled error on %s %s (%sms)",
            request.method,
            request.url.path,
            duration_ms,
        )
        raise

    duration_ms = round((time() - started_at) * 1000, 2)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    attach_csrf_cookie(request, response)
    if not request.url.path.startswith("/static"):
        logger.info(
            "%s %s -> %s (%sms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
    return response

# ---------------------- DB ----------------------
ensure_schema_sql = [
    ("users", "account_instance_id", "ALTER TABLE users ADD COLUMN account_instance_id TEXT"),
    ("users", "avatar_filename", "ALTER TABLE users ADD COLUMN avatar_filename TEXT"),
    ("users", "signed_prekey", "ALTER TABLE users ADD COLUMN signed_prekey TEXT"),
    ("users", "signed_prekey_signature", "ALTER TABLE users ADD COLUMN signed_prekey_signature TEXT"),
    ("users", "signed_prekey_key_id", "ALTER TABLE users ADD COLUMN signed_prekey_key_id INTEGER"),
    ("chats", "user1_hidden", "ALTER TABLE chats ADD COLUMN user1_hidden BOOLEAN NOT NULL DEFAULT FALSE"),
    ("chats", "user2_hidden", "ALTER TABLE chats ADD COLUMN user2_hidden BOOLEAN NOT NULL DEFAULT FALSE"),
    ("chats", "user1_cleared_at", "ALTER TABLE chats ADD COLUMN user1_cleared_at TIMESTAMP"),
    ("chats", "user2_cleared_at", "ALTER TABLE chats ADD COLUMN user2_cleared_at TIMESTAMP"),
    ("messages", "delivered_at", "ALTER TABLE messages ADD COLUMN delivered_at TIMESTAMP"),
    ("messages", "read_at", "ALTER TABLE messages ADD COLUMN read_at TIMESTAMP"),
    ("messages", "attachment_kind", "ALTER TABLE messages ADD COLUMN attachment_kind TEXT"),
    ("messages", "attachment_url", "ALTER TABLE messages ADD COLUMN attachment_url TEXT"),
    ("messages", "attachment_name", "ALTER TABLE messages ADD COLUMN attachment_name TEXT"),
    ("messages", "attachment_mime_type", "ALTER TABLE messages ADD COLUMN attachment_mime_type TEXT"),
    ("messages", "attachment_size", "ALTER TABLE messages ADD COLUMN attachment_size INTEGER"),
    ("messages", "attachment_meta", "ALTER TABLE messages ADD COLUMN attachment_meta TEXT"),
    ("messages", "sender_device_id", "ALTER TABLE messages ADD COLUMN sender_device_id TEXT"),
    ("messages", "deleted_for_all_at", "ALTER TABLE messages ADD COLUMN deleted_for_all_at TIMESTAMP"),
    ("messages", "deleted_for_all_by_user_id", "ALTER TABLE messages ADD COLUMN deleted_for_all_by_user_id INTEGER"),
]

# Let SQLAlchemy create all missing tables with dialect-correct types first.
Base.metadata.create_all(bind=engine)

inspector = inspect(engine)
existing_tables = set(inspector.get_table_names())

with engine.begin() as connection:
    for table_name, column_name, ddl in ensure_schema_sql:
        if table_name not in existing_tables:
            continue
        existing_columns = {column["name"] for column in inspector.get_columns(table_name)}
        if column_name not in existing_columns:
            try:
                connection.execute(text(ddl))
            except OperationalError as error:
                if "duplicate column name" not in str(error).lower():
                    raise

# ---------------------- Роутери ----------------------
app.include_router(auth.router)
app.include_router(messages.router)

# ---------------------- Корінь ----------------------
@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})
