# syntax=docker/dockerfile:1
FROM node:22-bookworm-slim AS frontend

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY assets ./assets
COPY templates ./templates
RUN npm run build:css

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    SQLITE_PATH=/app/data/db.sqlite3 \
    MEDIA_ROOT=/app/data/media \
    DEBUG=false \
    STORAGE_BACKEND=filesystem

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.12.1 /uv /uvx /bin/

COPY pyproject.toml uv.lock /app/
RUN uv sync --frozen --no-dev --no-install-project

COPY . /app
COPY --from=frontend /app/static/css/site.css /app/static/css/site.css

RUN DEBUG=true \
    SECRET_KEY=build-only-not-for-runtime \
    STORAGE_BACKEND=filesystem \
    IDENTITY_JWKS_URL=http://localhost:8000/.well-known/jwks.json \
    uv run python manage.py collectstatic --noinput --skip-checks

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app \
    && chmod +x /app/tools/docker-entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"

VOLUME ["/app/data"]

EXPOSE 8000

ENTRYPOINT ["/app/tools/docker-entrypoint.sh"]
