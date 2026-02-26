import uuid

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
from app.utils.jwt import (
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from app.dependencies.auth import get_current_user
from fastapi import Depends

# rate limit
from app.core.rate_limit import login_attempts, MAX_ATTEMPTS, WINDOW_SECONDS

from time import time
import random
from fastapi import Form
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from fastapi.templating import Jinja2Templates
from fastapi import Request, Depends
email_adapter = TypeAdapter(EmailStr)

router = APIRouter()
templates = Jinja2Templates(
    directory=os.getenv("TEMPLATES_DIR", "/code/client/templates")
)

REFRESH_TOKEN_EXPIRE_DAYS = int(
    os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7)
)


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

    try:
        existing_user = db.query(User).filter(
            User.email == valid_email
        ).first()

        if existing_user:
            return templates.TemplateResponse(
                "register.html",
                {"request": request, "error": "Користувач вже існує"},
                status_code=400
            )

        hashed_pw = hash_password(password)

        temp_username = f"tmp_{uuid.uuid4().hex}"
        # ⬇ створюємо без username
        user = User(
            email=valid_email,
            password=hashed_pw,
            username=temp_username
        )

        db.add(user)
        db.flush()  # ← БД присвоює id, але commit ще НЕ відбувся

        # тепер id вже є
        user.username = f"user{user.id}"

        db.commit()  # один єдиний commit

    finally:
        db.close()

    return RedirectResponse("/login", status_code=303)

# --------------------- ЛОГІН ---------------------

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):

    # ---- RATE LIMIT ----
    ip = request.client.host
    now = time()

    attempts = login_attempts[ip]
    login_attempts[ip] = [t for t in attempts if now - t < WINDOW_SECONDS]

    if len(login_attempts[ip]) >= MAX_ATTEMPTS:
        raise HTTPException(
            status_code=429,
            detail="Забагато спроб. Спробуйте пізніше."
        )

    login_attempts[ip].append(now)
    # --------------------

    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Невірний формат email"},
            status_code=400
        )

    db: Session = SessionLocal()

    try:
        user = db.query(User).filter(
            User.email == valid_email
        ).first()

        if not user or not verify_password(password, user.password):
            return templates.TemplateResponse(
                "login.html",
                {"request": request, "error": "Неправильний email або пароль"},
                status_code=400
            )

        # 🔐 Access token
        access_token = create_access_token({"sub": user.email})

        # 🔄 Refresh token
        refresh_token = create_refresh_token()
        hashed_refresh = hash_refresh_token(refresh_token)
        expires_at = datetime.utcnow() + timedelta(
            days=REFRESH_TOKEN_EXPIRE_DAYS
        )

        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host

        refresh_record = RefreshToken(
            token=hashed_refresh,
            user_id=user.id,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address
        )

        db.add(refresh_record)
        db.commit()

    finally:
        db.close()

    response = RedirectResponse("/profile", status_code=303)

    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return response


# --------------------- REFRESH ---------------------

@router.post("/refresh")
def refresh_token_route(
    request: Request,
    refresh_token: str = Cookie(None)
):

    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Немає refresh токена"
        )

    db: Session = SessionLocal()

    try:
        hashed_refresh = hash_refresh_token(refresh_token)

        token_record = db.query(RefreshToken).filter(
            RefreshToken.token == hashed_refresh
        ).first()

        if not token_record or token_record.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=401,
                detail="Недійсний refresh токен"
            )

        # ---- DEVICE CHECK ----
        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host

        if (
            token_record.user_agent != user_agent or
            token_record.ip_address != ip_address
        ):
            db.delete(token_record)
            db.commit()
            raise HTTPException(
                status_code=401,
                detail="Device mismatch"
            )
        # ----------------------

        user = db.query(User).filter(
            User.id == token_record.user_id
        ).first()

        if not user:
            db.delete(token_record)
            db.commit()
            raise HTTPException(
                status_code=401,
                detail="Користувач не існує"
            )

        # 🔁 ROTATION
        db.delete(token_record)

        new_refresh_token = create_refresh_token()
        new_hashed_refresh = hash_refresh_token(new_refresh_token)

        new_refresh_record = RefreshToken(
            token=new_hashed_refresh,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(
                days=REFRESH_TOKEN_EXPIRE_DAYS
            ),
            user_agent=user_agent,
            ip_address=ip_address
        )

        db.add(new_refresh_record)
        db.commit()

    finally:
        db.close()

    new_access_token = create_access_token({"sub": user.email})

    response = RedirectResponse("/profile", status_code=303)

    response.set_cookie(
        "access_token",
        new_access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

    response.set_cookie(
        "refresh_token",
        new_refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return response


# --------------------- LOGOUT ---------------------

@router.post("/logout")
def logout(refresh_token: str = Cookie(None)):

    db: Session = SessionLocal()

    try:
        if refresh_token:
            hashed_refresh = hash_refresh_token(refresh_token)

            db.query(RefreshToken).filter(
                RefreshToken.token == hashed_refresh
            ).delete()

            db.commit()
    finally:
        db.close()

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return response


 

@router.get("/profile", response_class=HTMLResponse)
def profile_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    return templates.TemplateResponse(
        "profile.html",
        {
            "request": request,
            "email": current_user.email,
            "name": current_user.username  # ← передаємо username як name
        }
    )
@router.post("/profile")
def update_profile(
    request: Request,
    name: str = Form(...),
    current_user: User = Depends(get_current_user)
):
    db: Session = SessionLocal()

    try:
        # 🔎 перевіряємо чи зайняте ім'я
        existing_user = (
            db.query(User)
            .filter(User.username == name)
            .first()
        )

        if existing_user and existing_user.id != current_user.id:
            return templates.TemplateResponse(
                "profile.html",
                {
                    "request": request,
                    "email": current_user.email,
                    "name": current_user.username,
                    "error": "Це ім'я вже зайняте"
                }
            )

        # ✅ якщо не зайняте — оновлюємо
        user = db.query(User).filter(User.id == current_user.id).first()
        user.username = name
        db.commit()

    finally:
        db.close()

    return RedirectResponse("/profile", status_code=303)