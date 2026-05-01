import os
import secrets
import uuid
import logging
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

from app.core.rate_limit import (
    FORGOT_PASSWORD_MAX_ATTEMPTS,
    FORGOT_PASSWORD_WINDOW_SECONDS,
    MAX_ATTEMPTS,
    WINDOW_SECONDS,
    forgot_password_attempts,
    login_attempts,
)
from app.db.models import OneTimePreKey, PasswordResetToken, RefreshToken, User
from app.db.session import SessionLocal
from app.dependencies.auth import get_current_user
from app.utils.avatar import build_avatar_props
from app.utils.jwt import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES,
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
audit_logger = logging.getLogger("app.audit")


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
    message: str | None = None,
    name_override: str | None = None,
    email_override: str | None = None,
):
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "request": request,
            "email": email_override if email_override is not None else current_user.email,
            "name": name_override if name_override is not None else current_user.username,
            "init_keys": True,
            "error": error,
            "message": message,
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


def set_auth_cookies(response, access_token: str, refresh_token: str):
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
        audit_logger.warning("register_invalid_email ip=%s email=%s", request.client.host, email)
        return templates.TemplateResponse(
            request,
            "register.html",
            {"request": request, "error": "РќРµРІС–СЂРЅРёР№ С„РѕСЂРјР°С‚ email", "email": email},
            status_code=400,
        )

    db: Session = SessionLocal()
    try:
        existing_user = db.query(User).filter(User.email == valid_email).first()
        if existing_user:
            audit_logger.warning("register_duplicate ip=%s email=%s", request.client.host, valid_email)
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
        audit_logger.info("register_success ip=%s user_id=%s email=%s", request.client.host, user.id, valid_email)
    except IntegrityError:
        db.rollback()
        audit_logger.warning("register_integrity_error ip=%s email=%s", request.client.host, valid_email)
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
    ip = request.client.host
    now = time()
    attempts = forgot_password_attempts[ip]
    forgot_password_attempts[ip] = [
        attempt for attempt in attempts if now - attempt < FORGOT_PASSWORD_WINDOW_SECONDS
    ]
    if len(forgot_password_attempts[ip]) >= FORGOT_PASSWORD_MAX_ATTEMPTS:
        audit_logger.warning("forgot_password_rate_limited ip=%s", ip)
        raise HTTPException(status_code=429, detail="Too many password reset attempts. Try again later.")
    forgot_password_attempts[ip].append(now)

    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        audit_logger.warning("forgot_password_invalid_email ip=%s email=%s", ip, email)
        return templates.TemplateResponse(
            request,
            "forgot_password.html",
            {"request": request, "email": email, "error": "Invalid email format", "message": None},
            status_code=400,
        )

    if not is_mail_configured():
        audit_logger.error("forgot_password_mail_not_configured ip=%s email=%s", ip, valid_email)
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
        user_id = user.id if user else None
        if user:
            db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete()
            token_id = secrets.token_urlsafe(32)
            db.add(
                PasswordResetToken(
                    token_id=token_id,
                    user_id=user.id,
                    expires_at=utc_now() + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
                )
            )
            db.commit()
        else:
            token_id = None
    finally:
        db.close()

    if user and token_id:
        token = create_password_reset_token(valid_email, token_id)
        reset_link = str(request.url_for("reset_password_page")) + f"?token={token}"
        send_password_reset_email(valid_email, reset_link)
        audit_logger.info("forgot_password_email_sent ip=%s user_id=%s email=%s", ip, user_id, valid_email)
    else:
        audit_logger.info("forgot_password_requested_unknown_email ip=%s email=%s", ip, valid_email)

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
        audit_logger.warning("password_reset_invalid_token ip=%s", request.client.host)
        return templates.TemplateResponse(
            request,
            "reset_password.html",
            {"request": request, "token": token, "error": "Reset link is invalid or expired.", "message": None},
            status_code=400,
        )

    if password != confirm_password:
        audit_logger.warning("password_reset_mismatch ip=%s email=%s", request.client.host, payload.get("sub"))
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
            audit_logger.warning("password_reset_user_not_found ip=%s email=%s", request.client.host, payload.get("sub"))
            return templates.TemplateResponse(
                request,
                "reset_password.html",
                {"request": request, "token": token, "error": "User not found.", "message": None},
                status_code=404,
            )

        token_record = (
            db.query(PasswordResetToken)
            .filter(
                PasswordResetToken.token_id == payload["jti"],
                PasswordResetToken.user_id == user.id,
            )
            .first()
        )
        if (
            not token_record
            or token_record.used_at is not None
            or token_record.expires_at < utc_now()
        ):
            audit_logger.warning("password_reset_rejected ip=%s email=%s", request.client.host, user.email)
            return templates.TemplateResponse(
                request,
                "reset_password.html",
                {"request": request, "token": token, "error": "Reset link is invalid or expired.", "message": None},
                status_code=400,
            )

        user.password = hash_password(password)
        db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()
        token_record.used_at = utc_now()
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete()
        db.commit()
        audit_logger.info("password_reset_success ip=%s user_id=%s email=%s", request.client.host, user.id, user.email)
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
        audit_logger.warning("login_rate_limited ip=%s", ip)
        raise HTTPException(status_code=429, detail="Забагато спроб. Спробуйте пізніше.")
    login_attempts[ip].append(now)

    try:
        valid_email = str(email_adapter.validate_python(email))
    except ValidationError:
        audit_logger.warning("login_invalid_email ip=%s email=%s", ip, email)
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
            audit_logger.warning("login_failed ip=%s email=%s", ip, valid_email)
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
        audit_logger.info("login_success ip=%s user_id=%s email=%s", ip, user.id, user.email)
    finally:
        db.close()

    response = RedirectResponse("/profile", status_code=303)
    set_auth_cookies(response, access_token, refresh_token)
    return response


@router.post("/refresh")
def refresh_token_route(request: Request, refresh_token: str = Cookie(None)):
    if not refresh_token:
        audit_logger.warning("refresh_missing_token ip=%s", request.client.host)
        raise HTTPException(status_code=401, detail="Немає refresh токена")

    db: Session = SessionLocal()
    try:
        hashed_refresh = hash_refresh_token(refresh_token)
        token_record = db.query(RefreshToken).filter(RefreshToken.token == hashed_refresh).first()
        if not token_record or token_record.expires_at < utc_now():
            audit_logger.warning("refresh_invalid_token ip=%s", request.client.host)
            raise HTTPException(status_code=401, detail="Недійсний refresh токен")

        user_agent = request.headers.get("user-agent")
        ip_address = request.client.host
        if token_record.user_agent != user_agent or token_record.ip_address != ip_address:
            db.delete(token_record)
            db.commit()
            audit_logger.warning("refresh_device_mismatch ip=%s token_user_id=%s", request.client.host, token_record.user_id)
            raise HTTPException(status_code=401, detail="Device mismatch")

        user = db.query(User).filter(User.id == token_record.user_id).first()
        if not user:
            db.delete(token_record)
            db.commit()
            audit_logger.warning("refresh_user_missing ip=%s user_id=%s", request.client.host, token_record.user_id)
            raise HTTPException(status_code=401, detail="Користувач не існує")

        ensure_account_instance_id(user, db)
        user_email = user.email
        token_record.expires_at = utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        db.commit()
        audit_logger.info("refresh_success ip=%s user_id=%s email=%s", request.client.host, user.id, user.email)
    finally:
        db.close()

    new_access_token = create_access_token({"sub": user_email})
    wants_json = (
        request.headers.get("x-requested-with") == "fetch"
        or "application/json" in request.headers.get("accept", "")
    )
    response = JSONResponse({"status": "ok"}) if wants_json else RedirectResponse("/profile", status_code=303)
    set_auth_cookies(response, new_access_token, refresh_token)
    return response


@router.post("/logout")
def logout(refresh_token: str = Cookie(None)):
    db: Session = SessionLocal()
    try:
        if refresh_token:
            deleted = db.query(RefreshToken).filter(RefreshToken.token == hash_refresh_token(refresh_token)).delete()
            db.commit()
            audit_logger.info("logout token_deleted=%s", deleted)
        else:
            audit_logger.info("logout_without_refresh_cookie")
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
    action: str = Form("profile"),
    name: str = Form(""),
    email: str = Form(""),
    current_password: str = Form(""),
    avatar: UploadFile | None = File(None),
    current_user: User = Depends(get_current_user),
):
    db: Session = SessionLocal()
    user: User | None = None
    try:
        user = db.query(User).filter(User.id == current_user.id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if action == "change_email":
            try:
                valid_email = str(email_adapter.validate_python(email))
            except ValidationError:
                audit_logger.warning("email_change_invalid_email user_id=%s email=%s", current_user.id, email)
                return render_profile_page(
                    request,
                    user,
                    error="РќРµРІС–СЂРЅРёР№ С„РѕСЂРјР°С‚ email",
                    email_override=email,
                )

            if not current_password or not verify_password(current_password, user.password):
                audit_logger.warning("email_change_invalid_password user_id=%s", current_user.id)
                return render_profile_page(
                    request,
                    user,
                    error="РќРµРІС–СЂРЅРёР№ РїРѕС‚РѕС‡РЅРёР№ РїР°СЂРѕР»СЊ",
                    email_override=valid_email,
                )

            existing_email_user = db.query(User).filter(User.email == valid_email).first()
            if existing_email_user and existing_email_user.id != user.id:
                audit_logger.warning("email_change_duplicate user_id=%s email=%s", current_user.id, valid_email)
                return render_profile_page(
                    request,
                    user,
                    error="Р¦РµР№ email РІР¶Рµ РІРёРєРѕСЂРёСЃС‚РѕРІСѓС”С‚СЊСЃСЏ",
                    email_override=valid_email,
                )

            old_email = user.email
            user.email = valid_email
            db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()

            new_access_token = create_access_token({"sub": user.email})
            new_refresh_token = create_refresh_token()
            db.add(
                RefreshToken(
                    token=hash_refresh_token(new_refresh_token),
                    user_id=user.id,
                    expires_at=utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
                    user_agent=request.headers.get("user-agent"),
                    ip_address=request.client.host,
                )
            )
            db.commit()
            audit_logger.info(
                "email_change_success user_id=%s old_email=%s new_email=%s",
                user.id,
                old_email,
                user.email,
            )

            response = RedirectResponse("/profile", status_code=303)
            set_auth_cookies(response, new_access_token, new_refresh_token)
            return response

        existing_user = db.query(User).filter(User.username == name).first()
        if existing_user and existing_user.id != current_user.id:
            audit_logger.warning("profile_update_duplicate_name user_id=%s attempted_name=%s", current_user.id, name)
            return render_profile_page(
                request,
                user,
                error="Р¦Рµ С–Рј'СЏ РІР¶Рµ Р·Р°Р№РЅСЏС‚Рµ",
                name_override=name,
            )

        user.username = name
        if avatar and avatar.filename:
            new_avatar_filename = save_avatar_file(avatar)
            old_avatar_filename = user.avatar_filename
            user.avatar_filename = new_avatar_filename
            db.commit()
            remove_avatar_file(old_avatar_filename)
            audit_logger.info("profile_avatar_updated user_id=%s", user.id)
            return RedirectResponse("/profile", status_code=303)

        db.commit()
        audit_logger.info("profile_updated user_id=%s", user.id)
    except ValueError as exc:
        db.rollback()
        audit_logger.warning("profile_update_invalid_avatar user_id=%s", current_user.id)
        return render_profile_page(request, user or current_user, error=str(exc), name_override=name)
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
        audit_logger.info("legacy_keys_uploaded user_id=%s", user.id)
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
        audit_logger.info("x3dh_keys_uploaded user_id=%s one_time_prekeys=%s", user.id, len(data.one_time_prekeys))
    except Exception as exc:
        db.rollback()
        audit_logger.exception("x3dh_keys_upload_failed user_id=%s", current_user.id)
        return {"status": "error", "message": str(exc)}
    finally:
        db.close()

    return {"status": "ok"}
