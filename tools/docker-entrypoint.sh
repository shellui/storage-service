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

python3 /app/tools/nginx/render-conf.py /etc/nginx/conf.d/storage.conf
nginx -t

runuser -u appuser -- gunicorn \
  --bind 127.0.0.1:8001 \
  --pid /tmp/gunicorn.pid \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-2}" \
  --timeout "${GUNICORN_TIMEOUT:-120}" \
  config.wsgi:application &
GUNICORN_PID=$!

python -c "
import socket, sys, time
for _ in range(50):
    try:
        socket.create_connection(('127.0.0.1', 8001), 1).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.1)
sys.stderr.write('Gunicorn did not become ready on 127.0.0.1:8001\n')
sys.exit(1)
"

nginx -g 'daemon off;' &
NGINX_PID=$!

shutdown() {
  nginx -s quit 2>/dev/null || true
  kill "${GUNICORN_PID}" 2>/dev/null || true
}
trap shutdown TERM INT

wait "${NGINX_PID}"
shutdown
wait || true
