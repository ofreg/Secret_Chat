from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db.models import User
import os
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))

# --------------------- РЕЄСТРАЦІЯ ---------------------
@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    db: Session = SessionLocal()
    
    # Перевірка чи користувач вже існує
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        db.close()
        return templates.TemplateResponse("register.html", {"request": request, "error": "Користувач вже існує"})
    
    user = User(email=email, password=password)
    db.add(user)
    db.commit()
    db.close()
    return RedirectResponse("/login", status_code=303)

# --------------------- ЛОГІН ---------------------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    db: Session = SessionLocal()
    user = db.query(User).filter(User.email == email, User.password == password).first()
    db.close()
    
    if user:
        # Можна зробити сесію або просто редірект
        return RedirectResponse("/", status_code=303)
    else:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Неправильний email або пароль"})
