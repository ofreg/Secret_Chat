from fastapi import Depends, Cookie, HTTPException
from sqlalchemy.orm import Session
from app.utils.jwt import decode_access_token
from app.db.session import get_db
from app.db.models import User

def get_current_user(
    access_token: str = Cookie(None),
    db: Session = Depends(get_db)
):
    if not access_token:
        raise HTTPException(status_code=401, detail="Не авторизовано")
    
    payload = decode_access_token(access_token)

    if payload is None:
        raise HTTPException(status_code=401, detail="Невірний токен")

    email = payload.get("sub")

    user = db.query(User).filter(User.email == email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Користувач не існує")

    return user
