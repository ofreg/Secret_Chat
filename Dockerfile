FROM python:3.11

# Робоча папка в контейнері
WORKDIR /code

# Копіюємо requirements спочатку
COPY server/requirements.txt .

# Встановлюємо залежності
RUN pip install --no-cache-dir -r requirements.txt

# Копіюємо server та client
COPY server /code/server
COPY client /code/client

# Встановлюємо PYTHONPATH для імпорту app.*
ENV PYTHONPATH=/code/server

# Команда запуску
CMD ["uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
