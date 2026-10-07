#!/usr/bin/env bash
# Container entrypoint.
#
# Modes (first argument, default "web"):
#   web     migrate, then gunicorn plus the scheduler (Celery worker with embedded beat)
#   worker  only the scheduler; for a dedicated worker container from the same image
#   other   run the given command as appuser, for example: python manage.py shell
#
# Production (DEBUG false, the image default) requires REDIS_URL in web and worker modes:
# without it the entrypoint logs an error and exits 1 before migrations. Redis backs the
# shared cache and the scheduled jobs, so it is required even with SCHEDULER_ENABLED=false.
# The same rule is the authapi.E004 deploy check, run below by `check --deploy`.
# With DEBUG=true (local development), Redis stays optional: without it the web app runs
# alone and logs a warning.
#
# The scheduler needs REDIS_URL (or CELERY_BROKER_URL). Set SCHEDULER_ENABLED=false to
# keep it out of the web container. See docs/maintenance-jobs.md.
#
# Supervision: in web mode both processes run as children of this script. A SIGTERM or
# SIGINT is forwarded to both, and if either one exits the other is stopped and the
# container exits with that status, so Docker or Coolify restarts it.
set -euo pipefail

MODE="${1:-web}"
if [ "$#" -gt 0 ]; then
  shift
fi

APP_USER="${APP_USER:-appuser}"

log() {
  echo "entrypoint: $*" >&2
}

# Prefix that runs a command as appuser. setpriv execs the command directly, so it
# receives signals itself. runuser forks and SIGKILLs the child 2 seconds after a
# SIGTERM, which cuts graceful shutdown short.
AS_APP=(
  setpriv --reuid="${APP_USER}" --regid="${APP_USER}" --init-groups --
  env HOME="/home/${APP_USER}" USER="${APP_USER}"
)

# Same truthy values as config/settings.py (surrounding whitespace ignored).
is_true() {
  case "$(printf '%s' "${1:-}" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
    1 | true | yes | on) return 0 ;;
    *) return 1 ;;
  esac
}

# Set and not only whitespace (settings strips it).
is_set() {
  [ -n "$(printf '%s' "${1:-}" | tr -d '[:space:]')" ]
}

broker_configured() {
  is_set "${CELERY_BROKER_URL:-}" || is_set "${REDIS_URL:-}"
}

# DEBUG defaults to false, like config/settings.py (the image sets DEBUG=false).
require_redis_in_production() {
  if is_true "${DEBUG:-false}" || is_set "${REDIS_URL:-}"; then
    return 0
  fi
  log "ERROR: REDIS_URL is required when DEBUG is false (example: redis://redis:6379/0)."
  log "ERROR: Redis backs the shared cache and the scheduled jobs, so it is required also with SCHEDULER_ENABLED=false or CELERY_BROKER_URL set."
  log "ERROR: Add a Redis service and set REDIS_URL, or set DEBUG=true for local development only. See docs/configuration.md."
  exit 1
}

prepare_data_dir() {
  local sqlite_file sqlite_dir media_dir
  sqlite_file="${SQLITE_PATH:-/app/data/db.sqlite3}"
  sqlite_dir="$(dirname "${sqlite_file}")"
  media_dir="${MEDIA_ROOT:-/app/data/media}"
  mkdir -p "${sqlite_dir}" "${media_dir}/objects"
  chown -R "${APP_USER}:${APP_USER}" "${sqlite_dir}" "${media_dir}"
  if [ "${sqlite_dir}" = "/app/data" ] && [ -z "${POSTGRES_DATABASE_URL:-}" ]; then
    log "INFO: For persistent data when using --rm, run with a named volume: -v storage-service-data:/app/data"
  fi
}

gunicorn_cmd() {
  # Gunicorn 26 maps sync + --threads>1 to gthread; -k gthread makes that explicit in logs/ops.
  #
  # Note on --timeout: with gthread, the worker's main loop keeps sending heartbeats while
  # a handler thread is blocked, so --timeout does NOT kill a worker whose threads are stuck
  # on a slow upload. It only catches a frozen worker process. Large uploads are bounded by
  # the reverse proxy and MAX_UPLOAD_BYTES.
  #
  # --max-requests with jitter recycles workers over time.
  # --worker-tmp-dir /dev/shm keeps the heartbeat file off the container disk.
  # --keep-alive is above the reverse proxy idle time, so the proxy does not reuse a
  # connection gunicorn is closing (that gives random 502s).
  #
  # %(U)s is the path with no query string. Referer is replaced with "-" so a
  # setup_token or a sign-in URL in the request line is not written to stdout.
  # Share-link tokens sit in the path; gunicorn.access redacts them.
  GUNICORN_ARGS=(
    gunicorn
    --bind 0.0.0.0:8000
    --worker-class gthread
    --workers "${GUNICORN_WORKERS:-2}"
    --threads "${GUNICORN_THREADS:-2}"
    --timeout "${GUNICORN_TIMEOUT:-120}"
    --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT:-30}"
    --keep-alive "${GUNICORN_KEEP_ALIVE:-75}"
    --max-requests "${GUNICORN_MAX_REQUESTS:-1000}"
    --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER:-200}"
    --worker-tmp-dir /dev/shm
    --access-logfile -
    --error-logfile -
    --access-logformat '%(h)s %(l)s %(u)s %(t)s "%(m)s %(U)s %(H)s" %(s)s %(b)s "-" "%(a)s" %(M)sms req=%({x-request-id}o)s'
    config.wsgi:application
  )
}

scheduler_cmd() {
  # One worker process with a small thread pool, plus beat embedded in it (-B).
  # Threads keep memory low: a purge run (up to 5 minutes) never blocks webhook retries
  # with the default concurrency of 2. The beat schedule file goes to /tmp, which is
  # writable for appuser; losing it on restart only means beat starts a fresh schedule.
  # --quiet drops the startup banner, which prints the broker URL.
  SCHEDULER_ARGS=(
    celery -A config --quiet worker
    --beat
    --schedule "${CELERY_BEAT_SCHEDULE_FILE:-/tmp/celerybeat-schedule}"
    --pool threads
    --concurrency "${CELERY_WORKER_CONCURRENCY:-2}"
    --hostname "storage-service@%h"
    --without-gossip
    --without-mingle
    --without-heartbeat
  )
}

PIDS=()
STOP_SIGNAL=""

stop_children() {
  local pid
  for pid in "${PIDS[@]}"; do
    kill -TERM "${pid}" 2>/dev/null || true
  done
}

on_signal() {
  STOP_SIGNAL="$1"
  log "received ${STOP_SIGNAL}, stopping"
  stop_children
}

# Run with the commands already started in PIDS: forward SIGTERM and SIGINT, and exit as
# soon as one of them exits.
supervise() {
  trap 'on_signal SIGTERM' TERM
  trap 'on_signal SIGINT' INT

  local status=0
  set +e
  # Returns when the first child exits, or early when a trapped signal arrives.
  wait -n "${PIDS[@]}"
  status=$?
  stop_children
  wait "${PIDS[@]}"
  set -e
  if [ -n "${STOP_SIGNAL}" ]; then
    log "stopped"
    exit 0
  fi
  log "a process exited with status ${status}, stopping the container"
  if [ "${status}" -eq 0 ]; then
    status=1
  fi
  exit "${status}"
}

case "${MODE}" in
  web)
    require_redis_in_production
    prepare_data_dir
    "${AS_APP[@]}" python manage.py migrate --noinput
    "${AS_APP[@]}" python manage.py check --deploy
    gunicorn_cmd

    start_scheduler=false
    if ! is_true "${SCHEDULER_ENABLED:-true}"; then
      log "SCHEDULER_ENABLED=false: scheduled jobs are not started in this container."
    elif ! broker_configured; then
      # Only reachable with DEBUG=true: production already exited above.
      log "WARNING: REDIS_URL is not set (DEBUG=true), so scheduled jobs (retry_webhooks, purge_expired_data) are not running."
      log "WARNING: Set REDIS_URL to run them in this container. It is required when DEBUG is false. See docs/maintenance-jobs.md."
    else
      start_scheduler=true
    fi

    if [ "${start_scheduler}" = false ]; then
      exec "${AS_APP[@]}" "${GUNICORN_ARGS[@]}"
    fi

    scheduler_cmd
    "${AS_APP[@]}" "${GUNICORN_ARGS[@]}" &
    PIDS+=("$!")
    log "starting scheduler (Celery worker and beat)"
    "${AS_APP[@]}" "${SCHEDULER_ARGS[@]}" &
    PIDS+=("$!")
    supervise
    ;;
  worker)
    require_redis_in_production
    if ! broker_configured; then
      log "ERROR: worker mode needs REDIS_URL (or CELERY_BROKER_URL)."
      exit 1
    fi
    prepare_data_dir
    scheduler_cmd
    log "starting scheduler (Celery worker and beat)"
    exec "${AS_APP[@]}" "${SCHEDULER_ARGS[@]}"
    ;;
  *)
    prepare_data_dir
    exec "${AS_APP[@]}" "${MODE}" "$@"
    ;;
esac
