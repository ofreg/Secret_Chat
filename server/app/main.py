from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from collections import defaultdict
from time import time
import os

from app.routers import auth, messages
from app.db.base import Base
from app.db.session import engine
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

# ---------------------- DB ----------------------
Base.metadata.create_all(bind=engine)

# ---------------------- Роутери ----------------------
app.include_router(auth.router)
app.include_router(messages.router)

# ---------------------- Корінь ----------------------
@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})