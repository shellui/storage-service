#!/usr/bin/env sh
set -eu

SQLITE_FILE="${SQLITE_PATH:-/app/data/db.sqlite3}"
SQLITE_DIR="$(dirname "${SQLITE_FILE}")"
MEDIA_DIR="${MEDIA_ROOT:-/app/data/media}"

mkdir -p "${SQLITE_DIR}" "${MEDIA_DIR}/objects"
chown -R appuser:appuser "${SQLITE_DIR}" "${MEDIA_DIR}"

if [ "${SQLITE_DIR}" = "/app/data" ] && [ -z "${POSTGRES_DATABASE_URL:-}" ]; then
  echo "INFO: For persistent data when using --rm, run with a named volume: -v storage-service-data:/app/data" >&2
fi

runuser -u appuser -- python manage.py migrate --noinput
exec runuser -u appuser -- gunicorn \
  --bind 0.0.0.0:8000 \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  config.wsgi:application
