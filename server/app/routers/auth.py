import os
import secrets
import uuid
from datetime import timedelta
from pathlib import Path
from time import time
from typing import List

from fastapi import APIRouter, Cookie, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field, TypeAdapter, ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.rate_limit import MAX_ATTEMPTS, WINDOW_SECONDS, login_attempts
from app.db.models import OneTimePreKey, RefreshToken, User
from app.db.session import SessionLocal
from app.dependencies.auth import get_current_user
from app.utils.avatar import build_avatar_props
from app.utils.jwt import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_password_reset_token,
    hash_refresh_token,
)
from app.utils.mail import is_mail_configured, send_password_reset_email
from app.utils.security import hash_password, verify_password
from app.utils.time import utc_now


email_adapter = TypeAdapter(EmailStr)
router = APIRouter()
templates = Jinja2Templates(directory=os.getenv("TEMPLATES_DIR", "/code/client/templates"))

REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in {"1", "true", "yes", "on"}
AVATAR_UPLOAD_DIR = Path(os.getenv("AVATAR_UPLOAD_DIR", "client/static/uploads/avatars"))
MAX_AVATAR_SIZE_BYTES = int(os.getenv("MAX_AVATAR_SIZE_BYTES", 2 * 1024 * 1024))
ALLOWED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".gif"}


class OneTimePreKeySchema(BaseModel):
    key_id: int
    public_key: str


class PublicKeySchema(BaseModel):
    public_key: str
    identity_key: str | None = None
    signing_key: str | None = None
    signed_prekey: str | None = None
    signed_prekey_signature: str | None = None
    signed_prekey_key_id: int | None = None
    one_time_prekeys: List[OneTimePreKeySchema] = Field(default_factory=list)


def ensure_account_instance_id(user: User, db: Session) -> str:
    if user.account_instance_id:
        return user.account_instance_id

    user.account_instance_id = uuid.uuid4().hex
    db.commit()
    db.refresh(user)
    return user.account_instance_id


def render_profile_page(
    request: Request,
    current_user: User,
    *,
    error: str | None = None,
    name_override: str | None = None,
):
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "request": request,
            "email": current_user.email,
            "name": name_override if name_override is not None else current_user.username,
            "init_keys": True,
            "error": error,
            **build_avatar_props(current_user),
        },
    )


def save_avatar_file(upload: UploadFile) -> str:
    extension = Path(upload.filename or "").suffix.lower()
    if extension not in ALLOWED_AVATAR_EXTENSIONS:
        raise ValueError("Підтримуються лише JPG, PNG, WEBP або GIF")

    content = upload.file.read(MAX_AVATAR_SIZE_BYTES + 1)
    if len(content) > MAX_AVATAR_SIZE_BYTES:
        raise ValueError("Файл завеликий. Максимум 2 МБ")

    AVATAR_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(16)}{extension}"
    (AVATAR_UPLOAD_DIR / filename).write_bytes(content)
    return filename


def remove_avatar_file(filename: str | None):
    if not filename:
        return

    path = AVATAR_UPLOAD_DIR / filename
    if path.exists():
        path.unlink()


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html", {"request": request})


@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {"request": request, "email": "", "error": None, "message": None},
    )


@router.post("/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        return templates.TemplateResponse(
            request,
            "register.html",
            {"request": request, "error": "Невірний формат email", "email": email},
            status_code=400,
        )

    db: Session = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == valid_email).first()
        if existing_user:
            return templates.TemplateResponse(
                request,
                "register.html",
                {"request": request, "error": "Користувач вже існує", "email": valid_email},
                status_code=400,
            )

        user = User(
            email=valid_email,
            password=hash_password(password),
            username=f"tmp_{uuid.uuid4().hex}",
        )
        db.add(user)
        db.flush()
        user.username = f"user{user.id}"
        db.commit()
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(
            request,
            "register.html",
            {"request": request, "error": "Користувач вже існує", "email": valid_email},
            status_code=400,
        )
    finally:
        db.close()

    return RedirectResponse("/login", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"request": request})


@router.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_submit(request: Request, email: str = Form(...)):
    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        return templates.TemplateResponse(
            request,
            "forgot_password.html",
            {"request": request, "email": email, "error": "Invalid email format", "message": None},
            status_code=400,
        )

    if not is_mail_configured():
        return templates.TemplateResponse(
            request,
            "forgot_password.html",
            {
                "request": request,
                "email": valid_email,
                "error": "Password reset email is not configured yet.",
                "message": None,
            },
            status_code=503,
        )

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == valid_email).first()
    finally:
        db.close()

    if user:
        token = create_password_reset_token(valid_email)
        reset_link = str(request.url_for("reset_password_page")) + f"?token={token}"
        send_password_reset_email(valid_email, reset_link)

    return templates.TemplateResponse(
        request,
        "forgot_password.html",
        {
            "request": request,
            "email": valid_email,
            "error": None,
            "message": "If an account with this email exists, a reset link has been sent.",
        },
    )


@router.get("/reset-password", response_class=HTMLResponse, name="reset_password_page")
def reset_password_page(request: Request, token: str = ""):
    payload = decode_password_reset_token(token) if token else None
    if not payload:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {"request": request, "token": token, "error": "Reset link is invalid or expired.", "message": None},
            status_code=400,
        )

    return templates.TemplateResponse(
        request,
        "reset_password.html",
        {"request": request, "token": token, "error": None, "message": None},
    )


@router.post("/reset-password")
def reset_password_submit(
    request: Request,
    token: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    payload = decode_password_reset_token(token)
    if not payload:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {"request": request, "token": token, "error": "Reset link is invalid or expired.", "message": None},
            status_code=400,
        )

    if password != confirm_password:
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {"request": request, "token": token, "error": "Passwords do not match.", "message": None},
            status_code=400,
        )

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == payload["sub"]).first()
        if not user:
            return templates.TemplateResponse(
                request,
                "reset_password.html",
                {"request": request, "token": token, "error": "User not found.", "message": None},
                status_code=404,
            )

        user.password = hash_password(password)
        db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()
        db.commit()
    finally:
        db.close()

    return RedirectResponse("/login", status_code=303)


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    ip = request.client.host
    now = time()

    attempts = login_attempts[ip]
    login_attempts[ip] = [attempt for attempt in attempts if now - attempt < WINDOW_SECONDS]
    if len(login_attempts[ip]) >= MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Забагато спроб. Спробуйте пізніше.")
    login_attempts[ip].append(now)

    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"request": request, "error": "Невірний формат email"},
            status_code=400,
        )

    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.email == valid_email).first()
        if not user or not verify_password(password, user.password):
            return templates.TemplateResponse(
                request,
                "login.html",
                {"request": request, "error": "Неправильний email або пароль"},
                status_code=400,
            )

        ensure_account_instance_id(user, db)
        access_token = create_access_token({"sub": user.email})
        refresh_token = create_refresh_token()
        hashed_refresh = hash_refresh_token(refresh_token)

        db.add(
            RefreshToken(
                token=hashed_refresh,
                user_id=user.id,
                expires_at=utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
                user_agent=request.headers.get("user-agent"),
                ip_address=request.client.host,
            )
        )
        db.commit()
    finally:
        db.close()

    response = RedirectResponse("/profile", status_code=303)
    response.set_cookie(
        "access_token",
        access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )
    return response


@router.post("/refresh")
def refresh_token_route(request: Request, refresh_token: str = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Немає refresh токена")

    db: Session = SessionLocal()
    try:
        hashed_refresh = hash_refresh_token(refresh_token)
        token_record = db.query(RefreshToken).filter(RefreshToken.token == hashed_refresh).first()
        if not token_record or token_record.expires_at < utc_now():
            raise HTTPException(status_code=401, detail="Недійсний refresh токен")

        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host
        if token_record.user_agent != user_agent or token_record.ip_address != ip_address:
            db.delete(token_record)
            db.commit()
            raise HTTPException(status_code=401, detail="Device mismatch")

        user = db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            db.delete(token_record)
            db.commit()
            raise HTTPException(status_code=401, detail="Користувач не існує")

        ensure_account_instance_id(user, db)
        user_email = user.email
        token_record.expires_at = utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        db.commit()
    finally:
        db.close()

    new_access_token = create_access_token({"sub": user_email})
    wants_json = (
        request.headers.get("x-requested-with") == "fetch"
        or "application/json" in request.headers.get("accept", "")
    )
    response = JSONResponse({"status": "ok"}) if wants_json else RedirectResponse("/profile", status_code=303)
    response.set_cookie(
        "access_token",
        new_access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    response.set_cookie(
        "refresh_token",
        refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )
    return response


@router.post("/logout")
def logout(refresh_token: str = Cookie(None)):
    db: Session = SessionLocal()
    try:
        if refresh_token:
            db.query(RefreshToken).filter(RefreshToken.token == hash_refresh_token(refresh_token)).delete()
            db.commit()
    finally:
        db.close()

    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response


@router.get("/profile", response_class=HTMLResponse)
def profile_page(request: Request, current_user: User = Depends(get_current_user)):
    return render_profile_page(request, current_user)


@router.post("/profile")
def update_profile(
    request: Request,
    name: str = Form(...),
    avatar: UploadFile | None = File(None),
    current_user: User = Depends(get_current_user),
):
    db: Session = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.username == name).first()
        if existing_user and existing_user.id != current_user.id:
            return render_profile_page(
                request,
                current_user,
                error="Це ім'я вже зайняте",
                name_override=name,
            )

        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        user.username = name
        if avatar and avatar.filename:
            new_avatar_filename = save_avatar_file(avatar)
            old_avatar_filename = user.avatar_filename
            user.avatar_filename = new_avatar_filename
            db.commit()
            remove_avatar_file(old_avatar_filename)
            return RedirectResponse("/profile", status_code=303)

        db.commit()
    except ValueError as exc:
        db.rollback()
        return render_profile_page(request, current_user, error=str(exc), name_override=name)
    finally:
        db.close()

    return RedirectResponse("/profile", status_code=303)


@router.post("/users/keys")
def upload_keys(data: PublicKeySchema, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            return {"status": "error", "message": "Користувач не знайдений"}

        user.public_key = data.public_key
        db.commit()
    finally:
        db.close()

    return {"status": "ok"}


@router.post("/users/x3dh-keys")
def upload_x3dh_keys(data: PublicKeySchema, current_user: User = Depends(get_current_user)):
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            return {"status": "error", "message": "Користувач не знайдений"}

        user.public_key = data.public_key
        user.identity_key = data.identity_key or data.public_key
        user.signing_key = data.signing_key
        user.signed_prekey = data.signed_prekey
        user.signed_prekey_signature = data.signed_prekey_signature
        user.signed_prekey_key_id = data.signed_prekey_key_id

        db.query(OneTimePreKey).filter(OneTimePreKey.user_id == user.id).delete()
        for prekey in data.one_time_prekeys:
            db.add(
                OneTimePreKey(
                    user_id=user.id,
                    key_id=prekey.key_id,
                    public_key=prekey.public_key,
                )
            )

        db.commit()
    except Exception as exc:
        db.rollback()
        return {"status": "error", "message": str(exc)}
    finally:
        db.close()

    return {"status": "ok"}
