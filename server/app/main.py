from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from collections import defaultdict
from time import time
import os
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.routers import auth, messages
from app.db.base import Base
from app.db.session import engine
from sqlalchemy import inspect, text
from fastapi.staticfiles import StaticFiles
# ---------------------- Конфіг ----------------------
login_attempts = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 60

# Абсолютний шлях всередині контейнера
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))

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
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    return response

# ---------------------- DB ----------------------
Base.metadata.create_all(bind=engine)
ensure_schema_sql = [
    ("users", "account_instance_id", "ALTER TABLE users ADD COLUMN account_instance_id TEXT"),
    ("users", "avatar_filename", "ALTER TABLE users ADD COLUMN avatar_filename TEXT"),
    ("users", "signing_key", "ALTER TABLE users ADD COLUMN signing_key TEXT"),
    ("users", "signed_prekey", "ALTER TABLE users ADD COLUMN signed_prekey TEXT"),
    ("users", "signed_prekey_signature", "ALTER TABLE users ADD COLUMN signed_prekey_signature TEXT"),
    ("users", "signed_prekey_key_id", "ALTER TABLE users ADD COLUMN signed_prekey_key_id INTEGER"),
]

inspector = inspect(engine)
existing_tables = set(inspector.get_table_names())

with engine.begin() as connection:
    if "users" in existing_tables:
        existing_user_columns = {column["name"] for column in inspector.get_columns("users")}
        for table_name, column_name, ddl in ensure_schema_sql:
            if column_name not in existing_user_columns:
                connection.execute(text(ddl))

Base.metadata.create_all(bind=engine)

# ---------------------- Роутери ----------------------
app.include_router(auth.router)
app.include_router(messages.router)

# ---------------------- Корінь ----------------------
@app.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"request": request})
