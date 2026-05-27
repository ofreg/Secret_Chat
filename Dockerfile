FROM python:3.11

WORKDIR /code

COPY server/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server /code/server
COPY client /code/client

ENV PYTHONPATH=/code/server

RUN groupadd --system app && useradd --system --gid app --create-home --shell /usr/sbin/nologin app \
    && mkdir -p /code/client/static/uploads/avatars /code/client/static/uploads/messages /code/logs \
    && chown -R app:app /code

USER app

CMD ["uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
