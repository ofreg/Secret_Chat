#!/bin/sh
set -eu

cd /code/server

if [ "${RUN_DB_MIGRATIONS:-1}" = "1" ]; then
  alembic upgrade head
fi

if [ "${UVICORN_RELOAD:-0}" = "1" ]; then
  exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" --reload
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}"
