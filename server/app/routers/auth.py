from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db.models import User
import os
from fastapi.templating import Jinja2Templates
from app.utils.security import hash_password, verify_password
from pydantic import EmailStr, ValidationError, TypeAdapter
email_adapter = TypeAdapter(EmailStr)
router = APIRouter()
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))

# --------------------- РЕЄСТРАЦІЯ ---------------------
@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    
    try:
        valid_email = email_adapter.validate_python(email)
        valid_email = str(valid_email)  # для БД
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Невірний формат email"}
        )
    db: Session = SessionLocal()
    
    existing_user = db.query(User).filter(User.email == valid_email).first()
    if existing_user:
        db.close()
        return templates.TemplateResponse(
            "register.html", 
            {"request": request, "error": "Користувач вже існує"}
        )
    
    hashed_pw = hash_password(password)
    user = User(email=valid_email, password=hashed_pw)
    
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
    
    try:
        valid_email = email_adapter.validate_python(email)
        valid_email = str(valid_email)  # для БД
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Невірний формат email"}
        )

    db: Session = SessionLocal()
    user = db.query(User).filter(User.email == valid_email).first()
    db.close()
    
    if user and verify_password(password, user.password):
        # Авторизація пройшла
        return RedirectResponse("/", status_code=303)
    else:
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Неправильний email або пароль"}
        )
