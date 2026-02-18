import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
import secrets
import hashlib

SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7))

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY not set")
if len(SECRET_KEY) < 32:
    raise RuntimeError("JWT_SECRET_KEY too weak (min 32 chars)")


# ---------------- ACCESS ----------------

def create_access_token(data: dict):
    """
    Створює JWT access token з полем 'sub' і 'type' = 'access'
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({
        "exp": expire,
        "type": "access"
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str):
    """
    Декодує access token і перевіряє:
    - правильний тип токена
    - наявність 'sub'
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != "access":
            return None
        if "sub" not in payload:
            return None

        return payload

    except JWTError:
        return None


# ---------------- REFRESH ----------------

def create_refresh_token():
    """
    Створює випадковий refresh token
    """
    return secrets.token_urlsafe(64)


def hash_refresh_token(token: str):
    """
    Хешує refresh token для безпечного зберігання
    """
    return hashlib.sha256(token.encode()).hexdigest()
