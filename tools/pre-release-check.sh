#!/usr/bin/env bash
# Pre-release checklist for storage-service (see PUBLISH.md).
# Usage:
#   ./tools/pre-release-check.sh
#   ./tools/pre-release-check.sh --skip-docker
#   ./tools/pre-release-check.sh --image mytag
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

SERVICE_NAME='storage-service'
HEALTH_PATH='/storage/v1/health'
SKIP_DOCKER=0
IMAGE_TAG=""
HOST_PORT="${PRE_RELEASE_HOST_PORT:-}"
CONTAINER_NAME="${PRE_RELEASE_CONTAINER_NAME:-storage-release-smoke-$$}"

usage() {
  cat <<'EOF'
Usage: ./tools/pre-release-check.sh [options]

Automates the PUBLISH.md pre-release checklist:
  1. Version alignment (pyproject.toml ↔ CHANGELOG dated entry)
  2. No secrets in git / Docker build context
  3. Image smoke test (/storage/v1/health)

Options:
  --skip-docker     Skip Docker build and smoke test
  --image TAG       Image tag to build/run (default: shellui/storage-service:pre-release)
  --port PORT       Host port for smoke test (default: free port, or PRE_RELEASE_HOST_PORT)
  -h, --help        Show this help
EOF
}

log() { printf '==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
}

make_smoke_jwks() {
  # Static JWKS for DEBUG=false containers (no live identity dependency).
  uv run python - <<'PY'
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = key.public_key()
numbers = pub.public_numbers()

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def int_b64u(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return b64u(value.to_bytes(length, 'big'))

jwk = {
    'kty': 'RSA',
    'use': 'sig',
    'alg': 'RS256',
    'kid': 'pre-release-smoke',
    'n': int_b64u(numbers.n),
    'e': int_b64u(numbers.e),
}
print(json.dumps({'keys': [jwk]}, separators=(',', ':')))
PY
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-docker) SKIP_DOCKER=1; shift ;;
    --image)
      IMAGE_TAG="${2:-}"
      [[ -n "${IMAGE_TAG}" ]] || fail '--image requires a tag'
      shift 2
      ;;
    --port)
      HOST_PORT="${2:-}"
      [[ -n "${HOST_PORT}" ]] || fail '--port requires a value'
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done

command -v uv >/dev/null 2>&1 || fail 'uv is required (https://docs.astral.sh/uv/)'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required'

VERSION="$(
  uv run python - <<'PY'
import tomllib
from pathlib import Path
data = tomllib.loads(Path('pyproject.toml').read_text(encoding='utf-8'))
print(data['project']['version'])
PY
)"
[[ -n "${VERSION}" ]] || fail 'could not read project.version from pyproject.toml'

if [[ -z "${IMAGE_TAG}" ]]; then
  IMAGE_TAG="shellui/${SERVICE_NAME}:pre-release"
fi

if [[ -z "${HOST_PORT}" ]]; then
  HOST_PORT="$(pick_free_port)"
fi

log "Pre-release check for ${SERVICE_NAME} ${VERSION}"

# ---------------------------------------------------------------------------
# 1. Version alignment
# ---------------------------------------------------------------------------
log "1/3 Version alignment"

if ! grep -E "^## \[${VERSION}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" CHANGELOG.md >/dev/null; then
  fail "CHANGELOG.md must contain a dated entry exactly like: ## [${VERSION}] - YYYY-MM-DD"
fi
if grep -E "^## \[${VERSION}\] - .*MM-DD" CHANGELOG.md >/dev/null; then
  fail "CHANGELOG.md entry for ${VERSION} still has a placeholder date (MM-DD)"
fi

LOCK_VERSION="$(
  uv run python - <<PY
from pathlib import Path
import re
text = Path('uv.lock').read_text(encoding='utf-8')
m = re.search(
    r'(?m)^name = "${SERVICE_NAME}"\nversion = "([^"]+)"',
    text,
)
print(m.group(1) if m else '')
PY
)"
if [[ -n "${LOCK_VERSION}" && "${LOCK_VERSION}" != "${VERSION}" ]]; then
  fail "uv.lock ${SERVICE_NAME} version (${LOCK_VERSION}) != pyproject.toml (${VERSION})"
fi

printf 'OK: version %s aligned in pyproject.toml, CHANGELOG.md, and uv.lock\n' "${VERSION}"

# ---------------------------------------------------------------------------
# 2. No secrets in build context
# ---------------------------------------------------------------------------
log "2/3 Secrets / build context"

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  fail '.env is tracked by git — remove it from the repository'
fi
if [[ -f .env ]] && ! grep -qE '^\.env$' .gitignore; then
  fail '.env exists locally but is not listed in .gitignore'
fi
if tracked_db="$(git ls-files '*.sqlite3')"; then
  if [[ -n "${tracked_db}" ]]; then
    printf '%s\n' "${tracked_db}" >&2
    fail 'SQLite database files must not be tracked'
  fi
fi
grep -qE '^\.env$' .gitignore || fail '.gitignore must exclude .env'
grep -qE '^\.env$' .dockerignore || fail '.dockerignore must exclude .env'

printf 'OK: .env / sqlite not tracked; ignore files look correct\n'

if [[ "${SKIP_DOCKER}" -eq 1 ]]; then
  log 'Skipping Docker steps (--skip-docker)'
  log 'Pre-release check passed (partial)'
  exit 0
fi

command -v docker >/dev/null 2>&1 || fail 'docker is required for image checks (or pass --skip-docker)'

log "Building image ${IMAGE_TAG}"
docker build -t "${IMAGE_TAG}" .

log 'Verifying .env is absent from the image'
docker run --rm --entrypoint sh "${IMAGE_TAG}" \
  -c 'test ! -f /app/.env && echo "OK: .env not in image"'

# ---------------------------------------------------------------------------
# 3. Smoke test
# ---------------------------------------------------------------------------
log "3/3 Image smoke test (host port ${HOST_PORT})"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

export SECRET_KEY="${SECRET_KEY:-$(uv run python -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())')}"
export IDENTITY_JWKS="${IDENTITY_JWKS:-$(make_smoke_jwks)}"
[[ -n "${IDENTITY_JWKS}" ]] || fail 'failed to build smoke IDENTITY_JWKS'
export IDENTITY_ISSUER="${IDENTITY_ISSUER:-https://pre-release.test}"
export IDENTITY_AUDIENCE="${IDENTITY_AUDIENCE:-shellui}"

docker run --rm -d --name "${CONTAINER_NAME}" -p "${HOST_PORT}:8000" \
  -e SECRET_KEY \
  -e IDENTITY_JWKS \
  -e IDENTITY_ISSUER \
  -e IDENTITY_AUDIENCE \
  -e SECURE_SSL_REDIRECT=false \
  -e POSTGRES_SSL_REQUIRE=false \
  -e STORAGE_BACKEND=filesystem \
  -e ALLOWED_HOSTS=localhost,127.0.0.1 \
  "${IMAGE_TAG}" >/dev/null

log 'Waiting for Gunicorn…'
ready=0
body=""
for _ in $(seq 1 60); do
  body="$(curl -s "http://127.0.0.1:${HOST_PORT}${HEALTH_PATH}" || true)"
  if [[ -n "${body}" ]] && printf '%s' "${body}" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "${ready}" -ne 1 ]]; then
  printf 'ERROR: service did not become ready on %s (last body: %s)\n' \
    "${HEALTH_PATH}" "${body:-empty}" >&2
  printf '\n--- docker logs (%s) ---\n' "${CONTAINER_NAME}" >&2
  docker logs "${CONTAINER_NAME}" 2>&1 >&2 || true
  printf '--- end docker logs ---\n' >&2
  exit 1
fi

printf '%s' "${body}" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
assert doc.get("status") == "ok", doc
path = sys.argv[1]
print("OK: %s → status=ok version=%s" % (path, doc.get("version")))
' "${HEALTH_PATH}"

log "Pre-release check passed for ${VERSION}"
