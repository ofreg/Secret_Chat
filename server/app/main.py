from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.routers import auth
from app.db.base import Base
from app.db.session import engine
import os
from fastapi.templating import Jinja2Templates
app = FastAPI()

# Абсолютний шлях всередині контейнера
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))

Base.metadata.create_all(bind=engine)
app.include_router(auth.router)

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})
