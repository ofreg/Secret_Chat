from fastapi import Depends, Cookie, HTTPException
from app.utils.jwt import decode_access_token

def get_current_user(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Не авторизовано")
    
    payload = decode_access_token(access_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Невірний токен")
    
    return payload["sub"]
