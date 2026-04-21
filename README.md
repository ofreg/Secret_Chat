# Diplom Work Chat

Веб-застосунок для обміну повідомленнями на `FastAPI` з JWT-авторизацією, WebSocket-чатом, аватарками профілю та клієнтським E2EE flow на базі `X3DH + Double Ratchet`.

## Що вже є

- реєстрація, логін, профіль, logout
- access/refresh cookie-сесія
- пошук користувачів і створення чатів
- WebSocket-доставка повідомлень
- історія повідомлень після повторного відкриття чату
- safety fingerprint / MITM verification panel
- аватарки профілю
- backend-тести на auth, messages і websocket сценарії

## Структура

```text
client/
  static/
    js/        frontend modules
    uploads/   uploaded avatars
  templates/   Jinja2 templates

server/
  app/
    routers/        HTTP/WebSocket routes
    dependencies/   auth dependencies
    db/             models + sessions
    utils/          jwt, security, avatars, websocket manager
  tests/            pytest test suite
```

## Основні технології

- `FastAPI`
- `SQLAlchemy`
- `PostgreSQL`
- `WebSocket`
- `Jinja2`
- `pytest`
- browser-side crypto modules in `client/static/js`

## Швидкий запуск через Docker

### 1. Підготувати `.env`

Скопіюй `.env.example` у `.env` і за потреби зміни значення.

### 2. Запуск

```bash
docker compose up --build
```

Після запуску застосунок буде доступний на:

- [http://localhost:8000](http://localhost:8000)

## Локальний запуск без Docker

### 1. Встановити залежності

```bash
python -m venv venv
venv\Scripts\activate
pip install -r server/requirements.txt
```

### 2. Налаштувати змінні середовища

Потрібні щонайменше:

- `DATABASE_URL_SYNC`
- `DATABASE_URL_ASYNC`
- `JWT_SECRET_KEY`
- `TEMPLATES_DIR`
- `STATIC_DIR`

### 3. Запуск застосунку

```bash
uvicorn server.app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Тести

Основний прогін:

```bash
pytest server/tests -q
```

У проєкті вже є тести на:

- auth flow
- refresh/logout edge cases
- protected routes
- messages endpoints
- websocket delivery
- websocket reconnect/history order

## Auth модель

- `access_token` і `refresh_token` зберігаються в `HttpOnly` cookies
- `/refresh` продовжує життя існуючого refresh token, а не ротуює його на кожному запиті
- protected HTTP routes закриті через `Depends(get_current_user)`
- websocket routes перевіряють `access_token` з cookies перед підключенням
- password reset працює через email reset token

## Password reset email

Для скидання пароля потрібно заповнити SMTP-змінні в `.env`.

Для Gmail найзручніше використовувати:

- `SMTP_HOST=smtp.gmail.com`
- `SMTP_PORT=587`
- `SMTP_USERNAME=<ваш gmail>`
- `SMTP_PASSWORD=<app password, не звичайний пароль>`
- `SMTP_FROM_EMAIL=<той самий gmail>`
- `SMTP_FROM_NAME=<ім'я відправника, наприклад IT-Support>`
- `SMTP_USE_TLS=true`
- `MAIL_APP_NAME=<назва застосунку, наприклад Mail>`
- `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES=30`
- `FORGOT_PASSWORD_RATE_LIMIT_MAX_ATTEMPTS=5`
- `FORGOT_PASSWORD_RATE_LIMIT_WINDOW_SECONDS=300`

У застосунку є сторінки:

- `/forgot-password`
- `/reset-password?token=...`

## E2EE / client crypto

Frontend crypto живе в `client/static/js`:

- [crypto.js](/F:/Project/University/Diplom_work/client/static/js/crypto.js)
- [x3dh.js](/F:/Project/University/Diplom_work/client/static/js/x3dh.js)
- [doubleRatchet.js](/F:/Project/University/Diplom_work/client/static/js/doubleRatchet.js)
- [chatCrypto.js](/F:/Project/University/Diplom_work/client/static/js/chatCrypto.js)

Що важливо:

- plaintext повідомлень не кешується в IndexedDB
- local crypto state може бути скинутий через verification panel
- fingerprint використовується для ручної MITM-перевірки

## Messages frontend

`messages.js` уже розбитий на модулі:

- [messagesUi.js](/F:/Project/University/Diplom_work/client/static/js/messagesUi.js)
- [messagesSockets.js](/F:/Project/University/Diplom_work/client/static/js/messagesSockets.js)
- [messagesHistory.js](/F:/Project/University/Diplom_work/client/static/js/messagesHistory.js)
- [messagesChatFlow.js](/F:/Project/University/Diplom_work/client/static/js/messagesChatFlow.js)
- [messagesVerification.js](/F:/Project/University/Diplom_work/client/static/js/messagesVerification.js)

## Файли аватарок

Аватарки користувачів зберігаються тут:

- [client/static/uploads/avatars](/F:/Project/University/Diplom_work/client/static/uploads/avatars)

Ця папка додана в `.gitignore`, тому нові аватарки не мають потрапляти в git.

## Security headers

У middleware вже виставляються:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy`

## Логи

Файлове логування вже підтримується. За замовчуванням логи пишуться в:

- [logs](/F:/Project/University/Diplom_work/logs)

Основні файли:

- `app.log` — загальні application/request логи
- `error.log` — помилки та stack traces

Крім технічних request-логів, у `app.log` тепер також пишуться audit-style події без секретів:

- реєстрація
- логін / logout / refresh
- forgot password / password reset
- оновлення профілю
- завантаження ключів
- створення чату
- збереження повідомлень і websocket-підключення

Що навмисно не логується:

- паролі
- access/refresh/reset токени
- plaintext текст повідомлень

Через `.env` можна налаштувати:

- `LOG_DIR`
- `APP_LOG_LEVEL`
- `APP_LOG_MAX_BYTES`
- `APP_LOG_BACKUP_COUNT`

## Поточний стан

На поточному етапі стабілізовано:

- refresh/session flow
- чат після `Ctrl+F5` і spam `F5`
- search/start chat flow
- MITM / verification panel
- websocket reconnect/history order

## Known caveats

- frontend E2EE flow складний і потребує акуратних змін
- частина UX ще може бути дополірована
- production deploy потребує окремого проходу по секретах, cookie policy і конфігурації середовища
