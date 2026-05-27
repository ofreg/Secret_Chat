import secrets

from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates
from starlette.requests import HTTPConnection

CSRF_COOKIE_NAME = "csrf_token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def get_or_create_csrf_token(request: Request) -> str:
    state_token = getattr(request.state, "csrf_token", None)
    if state_token:
        return state_token

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    token = cookie_token or secrets.token_urlsafe(32)
    request.state.csrf_token = token
    return token


def configure_templates(templates: Jinja2Templates) -> Jinja2Templates:
    templates.env.globals["csrf_token"] = get_or_create_csrf_token
    return templates


def attach_csrf_cookie(request: Request, response) -> None:
    token = getattr(request.state, "csrf_token", None)
    if not token or request.cookies.get(CSRF_COOKIE_NAME) == token:
        return

    response.set_cookie(
        CSRF_COOKIE_NAME,
        token,
        httponly=False,
        secure=False,
        samesite="lax",
        path="/",
    )


async def require_csrf(conn: HTTPConnection) -> None:
    if conn.scope.get("type") == "websocket":
        return

    request = conn

    if request.method in SAFE_METHODS:
        return

    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    if not cookie_token:
        raise HTTPException(status_code=403, detail="CSRF token is missing")

    request_token = request.headers.get("X-CSRF-Token")
    if not request_token:
        try:
            form = await request.form()
        except Exception:
            form = None
        if form is not None:
            request_token = form.get("csrf_token")

    if not request_token or not secrets.compare_digest(cookie_token, request_token):
        raise HTTPException(status_code=403, detail="CSRF token is invalid")
