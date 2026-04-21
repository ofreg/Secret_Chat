import os
import time
import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from app.utils.logging_config import setup_logging


setup_logging()
logger = logging.getLogger("app.db.session")

DB_URL_SYNC = os.getenv("DATABASE_URL_SYNC") or (
    f"postgresql://{os.getenv('POSTGRES_USER')}:"
    f"{os.getenv('POSTGRES_PASSWORD')}@"
    f"{os.getenv('POSTGRES_HOST')}:"
    f"{os.getenv('POSTGRES_PORT')}/"
    f"{os.getenv('POSTGRES_DB')}"
)

DB_URL_ASYNC = os.getenv("DATABASE_URL_ASYNC") or DB_URL_SYNC.replace("postgresql://", "postgresql+asyncpg://")


# ✅ pool_pre_ping — перевіряє живість з'єднання
engine = create_engine(
    DB_URL_SYNC,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
)


async_engine = create_async_engine(
    DB_URL_ASYNC,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    expire_on_commit=False,
)


# 🔁 ЧЕКАЄМО ПОКИ БД СТАРТУЄ
def wait_for_db(max_retries: int = 10, delay: int = 2):
    if DB_URL_SYNC.startswith("sqlite"):
        return

    for attempt in range(max_retries):
        try:
            with engine.connect():
                logger.info("Database connected")
                return
        except OperationalError:
            logger.warning("Database not ready (attempt %s/%s)", attempt + 1, max_retries)
            time.sleep(delay)

    logger.error("Could not connect to database after multiple attempts")
    raise RuntimeError("Could not connect to database after multiple attempts")


wait_for_db()


def get_db():
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()
