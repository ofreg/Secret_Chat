import os
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import sessionmaker

DB_URL_SYNC = (
    f"postgresql://{os.getenv('POSTGRES_USER')}:"
    f"{os.getenv('POSTGRES_PASSWORD')}@"
    f"{os.getenv('POSTGRES_HOST')}:"
    f"{os.getenv('POSTGRES_PORT')}/"
    f"{os.getenv('POSTGRES_DB')}"
)

DB_URL_ASYNC = DB_URL_SYNC.replace("postgresql://", "postgresql+asyncpg://")

engine = create_engine(DB_URL_SYNC)
SessionLocal = sessionmaker(bind=engine)

async_engine = create_async_engine(DB_URL_ASYNC)
AsyncSessionLocal = async_sessionmaker(bind=async_engine)
