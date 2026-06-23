# EC2 Deploy

## Development

Use the default compose file for local development:

```bash
docker compose up --build
```

This mode keeps bind mounts and enables `uvicorn --reload`.

## Production on one EC2 instance

1. Copy `.env.production.example` to `.env` and fill in real secrets.
2. Build and start:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

3. Check logs:

```bash
docker compose -f docker-compose.prod.yml logs -f web
```

## Persistence

Production uses named Docker volumes:

- `postgres_data` for PostgreSQL
- `avatars_data` for uploaded avatars
- `messages_data` for uploaded message media

Because of that, database records, avatars, and media survive container recreation on the same EC2 host.
