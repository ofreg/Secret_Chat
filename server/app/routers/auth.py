from fastapi import APIRouter, Request, Form, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.db.session import SessionLocal
from app.db.models import User, RefreshToken
import os
from fastapi.templating import Jinja2Templates
from app.utils.security import hash_password, verify_password
from pydantic import EmailStr, ValidationError, TypeAdapter
from app.utils.jwt import create_access_token, create_refresh_token

email_adapter = TypeAdapter(EmailStr)

router = APIRouter()
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))

REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))

# --------------------- РЕЄСТРАЦІЯ ---------------------
@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@router.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):

    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Невірний формат email"},
            status_code=400
        )

    db: Session = SessionLocal()
    existing_user = db.query(User).filter(User.email == valid_email).first()

    if existing_user:
        db.close()
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Користувач вже існує"},
            status_code=400
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
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Невірний формат email"},
            status_code=400
        )

    db: Session = SessionLocal()
    user = db.query(User).filter(User.email == valid_email).first()

    if user and verify_password(password, user.password):

        # 🔐 Access token
        access_token = create_access_token({"sub": user.email})

        # 🔄 Refresh token
        refresh_token = create_refresh_token()
        expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

        refresh_record = RefreshToken(
            token=refresh_token,
            user_id=user.id,
            expires_at=expires_at
        )

        db.add(refresh_record)
        db.commit()
        db.close()

        response = RedirectResponse("/", status_code=303)
        response.set_cookie("access_token", access_token, httponly=True)
        response.set_cookie("refresh_token", refresh_token, httponly=True)

        return response

    db.close()
    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Неправильний email або пароль"},
        status_code=400
    )


# --------------------- REFRESH ---------------------
@router.post("/refresh")
def refresh_token_route(refresh_token: str = Cookie(None)):

    if not refresh_token:
        raise HTTPException(status_code=401, detail="Немає refresh токена")

    db: Session = SessionLocal()
    token_record = db.query(RefreshToken).filter(
        RefreshToken.token == refresh_token
    ).first()

    if not token_record or token_record.expires_at < datetime.utcnow():
        db.close()
        raise HTTPException(status_code=401, detail="Недійсний refresh токен")

    user = db.query(User).filter(User.id == token_record.user_id).first()
    db.close()

    new_access_token = create_access_token({"sub": user.email})

    response = RedirectResponse("/", status_code=303)
    response.set_cookie("access_token", new_access_token, httponly=True)

    return response


# --------------------- LOGOUT ---------------------
@router.post("/logout")
def logout(refresh_token: str = Cookie(None)):

    db: Session = SessionLocal()

    if refresh_token:
        db.query(RefreshToken).filter(
            RefreshToken.token == refresh_token
        ).delete()
        db.commit()

    db.close()

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response
