#!/usr/bin/env bash
# Dev stack entrypoint (Dockerfile target `dev`): install the bind-mounted project
# into /opt/venv, migrate, then Django runserver with autoreload.
set -euo pipefail

cd /app
uv sync --frozen --no-dev
python manage.py migrate --noinput
exec python manage.py runserver 0.0.0.0:8000
