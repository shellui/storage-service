#!/usr/bin/env bash
# Post-deploy production configuration smoke test for storage-service.
# Run against a live HTTPS deployment (storage API host, e.g. files.shellui.com).
#
# Usage:
#   ./tools/prod-config-check.sh https://files.shellui.com
#
# Optional env:
#   CORS_PROBE_ORIGIN    Origin for CORS preflight (default: random preview-style origin)
#   EXPECTED_IDENTITY_ISSUER   Manual JWT iss checklist (default: unset — printed as INFO)
#   EXPECTED_IDENTITY_AUDIENCE Manual JWT aud checklist (default: shellui)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: ./tools/prod-config-check.sh BASE_URL

Verify a deployed storage-service instance is correctly configured for production.

Environment (optional):
  CORS_PROBE_ORIGIN          Origin header for CORS preflight probe
  EXPECTED_IDENTITY_ISSUER   Expected JWT iss claim (informational checklist)
  EXPECTED_IDENTITY_AUDIENCE Expected JWT aud claim (default: shellui)

Checks: HTTPS reachability, /storage/v1/health, protected /storage/v1/* probes,
        bootstrap gate on /, CORS, identity JWKS wiring (via health + INFO),
        Postgres SSL notes (INFO), security headers (HSTS warn-only).

Exit 0 when all hard checks pass; non-zero if any FAIL.
EOF
}

pass() { printf 'PASS: %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; FAILURES=$((FAILURES + 1)); }
warn() { printf 'WARN: %s\n' "$*" >&2; }
info() { printf 'INFO: %s\n' "$*"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'FAIL: required command not found: %s\n' "$1" >&2
    exit 2
  }
}

normalize_base_url() {
  local url="${1%/}"
  if [[ ! "${url}" =~ ^https?:// ]]; then
    printf 'FAIL: BASE_URL must include scheme (https://…)\n' >&2
    exit 2
  fi
  printf '%s' "${url}"
}

url_origin() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit
parts = urlsplit(sys.argv[1])
print(f"{parts.scheme}://{parts.netloc}")
PY
}

FAILURES=0
BASE_URL=""
CORS_PROBE_ORIGIN="${CORS_PROBE_ORIGIN:-https://example-preview-slug.shellui.app}"
EXPECTED_IDENTITY_AUDIENCE="${EXPECTED_IDENTITY_AUDIENCE:-shellui}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    -*)
      printf 'FAIL: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
    *)
      if [[ -z "${BASE_URL}" ]]; then
        BASE_URL="$1"
      else
        printf 'FAIL: unexpected argument: %s\n' "$1" >&2
        exit 2
      fi
      shift
      ;;
  esac
done

[[ -n "${BASE_URL}" ]] || {
  usage >&2
  exit 2
}

require_cmd curl
require_cmd python3

BASE_URL="$(normalize_base_url "${BASE_URL}")"
ORIGIN="$(url_origin "${BASE_URL}")"

info "Target: ${BASE_URL}"
if [[ -n "${EXPECTED_IDENTITY_ISSUER:-}" ]]; then
  info "Expected JWT issuer (manual verify after login): ${EXPECTED_IDENTITY_ISSUER}"
else
  info "Expected JWT issuer: set EXPECTED_IDENTITY_ISSUER or IDENTITY_ISSUER in prod when DEBUG=false"
fi
info "Expected JWT audience (manual verify after login): ${EXPECTED_IDENTITY_AUDIENCE}"

# ---------------------------------------------------------------------------
# 1. Reachable (HTTPS, follow redirects)
# ---------------------------------------------------------------------------
reachable_meta="$(
  curl -sS -L -o /dev/null -w '%{http_code}\t%{url_effective}\t%{num_redirects}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/" 2>/dev/null || printf '000\t\t0'
)"
IFS=$'\t' read -r reach_code reach_final reach_redirects <<<"${reachable_meta}"

if [[ "${reach_code}" == "000" || -z "${reach_code}" ]]; then
  fail "Reachable: no response from ${BASE_URL}/ (connection/TLS/timeout)"
elif [[ "${reach_code}" =~ ^[45][0-9][0-9]$ ]]; then
  fail "Reachable: ${BASE_URL}/ returned HTTP ${reach_code} (final: ${reach_final:-unknown})"
else
  reach_note="HTTP ${reach_code}"
  if [[ "${reach_redirects:-0}" -gt 0 ]]; then
    reach_note="${reach_note}, ${reach_redirects} redirect(s) → ${reach_final}"
    if [[ "${BASE_URL}/" != "${reach_final}" && "${BASE_URL}" != "${reach_final}" ]]; then
      reach_note="${reach_note} (note SSL/host redirect)"
    fi
  fi
  if [[ "${reach_final}" == http://* && "${BASE_URL}" == https://* ]]; then
    warn "Reachable: final URL is HTTP after redirect (${reach_final}) — prefer HTTPS in production"
  fi
  pass "Reachable: ${reach_note}"
fi

# ---------------------------------------------------------------------------
# 2. Health GET /storage/v1/health
# ---------------------------------------------------------------------------
health_body="$(mktemp)"
health_code="$(
  curl -sS -L -o "${health_body}" -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/storage/v1/health" 2>/dev/null || echo '000'
)"

health_result="$(
  HEALTH_FILE="${health_body}" HEALTH_CODE="${health_code}" python3 <<'PY'
import json
import os
import re
import sys

code = os.environ["HEALTH_CODE"]
path = os.environ["HEALTH_FILE"]

if code == "000":
    print("FAIL\tno response from /storage/v1/health")
    sys.exit(0)
if code == "500":
    print("FAIL\tHTTP 500 — check database, JWKS, and container logs")
    sys.exit(0)
if code != "200":
    print(f"FAIL\tHTTP {code} (expected 200)")
    sys.exit(0)

try:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
except (OSError, json.JSONDecodeError) as exc:
    print(f"FAIL\tHTTP 200 but invalid JSON: {exc}")
    sys.exit(0)

if doc.get("status") != "ok":
    print(f"FAIL\tstatus={doc.get('status')!r} (expected 'ok')")
    sys.exit(0)

jwks_source = doc.get("identity_jwks_source") or "?"
jwks_url = doc.get("identity_jwks_url") or "?"
backend = doc.get("storage_backend") or "?"
version = doc.get("version") or "?"

detail = (
    f"status=ok version={version} storage_backend={backend} "
    f"identity_jwks_source={jwks_source} identity_jwks_url={jwks_url}"
)

leak_markers = [
    (r"localhost|127\.0\.0\.1", "localhost/127.0.0.1 in identity_jwks_url"),
    (r"^http://", "non-TLS identity_jwks_url on public health"),
    (r"\.internal\b|host\.docker\.internal", "internal Docker hostname in identity_jwks_url"),
]
if isinstance(jwks_url, str):
    for pattern, label in leak_markers:
        if re.search(pattern, jwks_url, re.I):
            print(f"PASS\t{detail}")
            print(f"WARN\tHealth exposes infra detail: {label} ({jwks_url}) — prefer IDENTITY_JWKS env/file in production")
            sys.exit(0)

print(f"PASS\t{detail}")
PY
)" || health_result=$'FAIL\thealth parse error'

health_status="${health_result%%$'\t'*}"
health_detail="${health_result#*$'\t'}"
case "${health_status}" in
  PASS)
    pass "Health: ${health_detail}"
    # Optional second line from python (WARN on infra leak)
    if [[ "${health_result}" == *$'\n'* ]]; then
      health_warn_line="$(printf '%s\n' "${health_result}" | sed -n '2p')"
      health_warn_status="${health_warn_line%%$'\t'*}"
      health_warn_detail="${health_warn_line#*$'\t'}"
      if [[ "${health_warn_status}" == "WARN" ]]; then
        warn "Health: ${health_warn_detail}"
      fi
    fi
    ;;
  WARN) warn "Health: ${health_detail}" ;;
  *) fail "Health: ${health_detail}" ;;
esac
rm -f "${health_body}"

# ---------------------------------------------------------------------------
# 3. Protected API surface (unauthenticated → 401/403, not 500)
# ---------------------------------------------------------------------------
for probe_path in '/storage/v1/bucket' '/storage/v1/quota' '/storage/v1/stats'; do
  probe_code="$(
    curl -sS -L -o /dev/null -w '%{http_code}' \
      --connect-timeout 15 --max-time 30 \
      "${BASE_URL}${probe_path}" 2>/dev/null || echo '000'
  )"
  if [[ "${probe_code}" == "500" ]]; then
    fail "API ${probe_path}: unauthenticated GET → HTTP 500 (misconfiguration — check JWKS/DB/logs)"
  elif [[ "${probe_code}" == "000" ]]; then
    fail "API ${probe_path}: no response"
  elif [[ "${probe_code}" =~ ^(401|403)$ ]]; then
    pass "API ${probe_path}: unauthenticated GET → HTTP ${probe_code} (auth required)"
  elif [[ "${probe_code}" =~ ^4[0-9][0-9]$ ]]; then
    pass "API ${probe_path}: unauthenticated GET → HTTP ${probe_code} (client error, not 500)"
  else
    warn "API ${probe_path}: unauthenticated GET → HTTP ${probe_code} (expected 401/403)"
  fi
done

# ---------------------------------------------------------------------------
# 4. Bootstrap gate (no open superuser form on apex)
# ---------------------------------------------------------------------------
home_body="$(mktemp)"
home_code="$(
  curl -sS -L -o "${home_body}" -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/" 2>/dev/null || echo '000'
)"

bootstrap_result="$(
  HOME_FILE="${home_body}" HOME_CODE="${home_code}" python3 <<'PY'
import os
import sys

path = os.environ["HOME_FILE"]
code = os.environ["HOME_CODE"]

if code == "000":
    print("FAIL\tno response from /")
    sys.exit(0)

try:
    html = open(path, encoding="utf-8", errors="replace").read().lower()
except OSError as exc:
    print(f"FAIL\tcould not read / body: {exc}")
    sys.exit(0)

markers = [
    "create superuser",
    "create the initial administrator",
    "initial administrator account",
    "show_setup_form",
]
hits = [m for m in markers if m in html]
if hits:
    print(
        "FAIL\t/ looks like open first-run superuser setup — prod should have users already "
        f"(matched: {', '.join(hits[:2])}). Ensure DEBUG=false and database is initialized."
    )
elif "shellui storage" in html or "openapi" in html or "swagger" in html:
    print("PASS\t/ does not expose open superuser signup (storage landing/docs page)")
elif code in {"301", "302", "303", "307", "308"}:
    print(f"PASS\t/ redirects (HTTP {code}) — bootstrap form not served at apex")
else:
    print("WARN\t/ HTML is ambiguous — could not confirm bootstrap gate; inspect manually")
PY
)" || bootstrap_result=$'WARN\t/ bootstrap check error'
rm -f "${home_body}"

bootstrap_status="${bootstrap_result%%$'\t'*}"
bootstrap_detail="${bootstrap_result#*$'\t'}"
case "${bootstrap_status}" in
  PASS) pass "Bootstrap gate: ${bootstrap_detail}" ;;
  WARN) warn "Bootstrap gate: ${bootstrap_detail}" ;;
  *) fail "Bootstrap gate: ${bootstrap_detail}" ;;
esac

# ---------------------------------------------------------------------------
# 5. Identity / JWKS dependency (informational + health cross-check)
# ---------------------------------------------------------------------------
info "JWT verification requires IDENTITY_JWKS, IDENTITY_JWKS_FILE, or IDENTITY_SERVICE_URL → /.well-known/jwks.json."
info "Production should pin JWKS locally (IDENTITY_JWKS / IDENTITY_JWKS_FILE) — avoid runtime HTTP to identity from the container."
info "Set IDENTITY_ISSUER / IDENTITY_AUDIENCE when DEBUG=false if tokens use non-default iss/aud."
info "Decode a post-login access_token JWT to confirm iss/aud match your identity deployment."

# ---------------------------------------------------------------------------
# 6. CORS (preview origins for API calls from hosted shells)
# ---------------------------------------------------------------------------
cors_headers="$(mktemp)"
cors_code="$(
  curl -sS -L -D "${cors_headers}" -o /dev/null -w '%{http_code}' \
    -X OPTIONS \
    -H "Origin: ${CORS_PROBE_ORIGIN}" \
    -H 'Access-Control-Request-Method: GET' \
    -H 'Access-Control-Request-Headers: authorization' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/storage/v1/health" 2>/dev/null || echo '000'
)"

cors_result="$(
  CORS_HDR_FILE="${cors_headers}" CORS_CODE="${cors_code}" CORS_ORIGIN="${CORS_PROBE_ORIGIN}" python3 <<'PY'
import os
import sys

hdr_path = os.environ["CORS_HDR_FILE"]
code = os.environ["CORS_CODE"]
origin = os.environ["CORS_ORIGIN"]

headers = {}
try:
    with open(hdr_path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
except OSError as exc:
    print(f"FAIL\tcould not read CORS headers: {exc}")
    sys.exit(0)

acao = headers.get("access-control-allow-origin")
if code == "000":
    print("FAIL\tOPTIONS preflight failed (no response)")
elif acao == "*":
    print(f"PASS\tAccess-Control-Allow-Origin: * (origin {origin})")
elif acao == origin:
    print(f"PASS\tAccess-Control-Allow-Origin reflects {origin}")
elif acao:
    print(
        f"WARN\tAccess-Control-Allow-Origin={acao!r} — random preview origins may be blocked; "
        "product default is allow-all (CORS_ALLOW_ALL_ORIGINS=true)"
    )
else:
    print(
        "FAIL\tno Access-Control-Allow-Origin on OPTIONS — random hosting preview origins will fail in the browser; "
        "set CORS_ALLOW_ALL_ORIGINS=true or add origins to CORS_ALLOWED_ORIGINS"
    )
PY
)"
rm -f "${cors_headers}"

cors_status="${cors_result%%$'\t'*}"
cors_detail="${cors_result#*$'\t'}"
case "${cors_status}" in
  PASS) pass "CORS: ${cors_detail}" ;;
  WARN) warn "CORS: ${cors_detail}" ;;
  *) fail "CORS: ${cors_detail}" ;;
esac

# ---------------------------------------------------------------------------
# 7. Postgres SSL (Coolify internal DB — informational)
# ---------------------------------------------------------------------------
info "Postgres: storage-service parses POSTGRES_DATABASE_URL with ssl_require=false (Coolify-internal Postgres often has no TLS)."
info "If boot fails with Postgres SSL errors against an internal Docker database, set POSTGRES_SSL_REQUIRE=false in orchestration (same gotcha as identity-service 0.5.0) or use an external Postgres with TLS."

# ---------------------------------------------------------------------------
# 8. Security headers (warn-only)
# ---------------------------------------------------------------------------
sec_headers="$(mktemp)"
sec_code="$(
  curl -sS -L -D "${sec_headers}" -o /dev/null -w '%{http_code}' \
    --connect-timeout 15 --max-time 30 \
    "${BASE_URL}/" 2>/dev/null || echo '000'
)"

if [[ "${BASE_URL}" == https://* ]]; then
  if grep -qi '^strict-transport-security:' "${sec_headers}" 2>/dev/null; then
    hsts_val="$(grep -i '^strict-transport-security:' "${sec_headers}" | head -1 | cut -d: -f2- | xargs)"
    pass "Security headers: Strict-Transport-Security present (${hsts_val})"
  else
    warn "Security headers: Strict-Transport-Security missing on HTTPS response (configure reverse proxy or Django SECURE_HSTS_*)"
  fi
else
  info "Security headers: skipped HSTS check (BASE_URL is not HTTPS)"
fi
rm -f "${sec_headers}"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [[ "${FAILURES}" -gt 0 ]]; then
  printf '\n%d check(s) failed.\n' "${FAILURES}" >&2
  exit 1
fi

printf '\nAll hard checks passed.\n'
exit 0
