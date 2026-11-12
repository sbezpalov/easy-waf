#!/usr/bin/env bash
# End-to-end backup / factory-reset / restore check (appliance with easy-waf-api).
#
#   sudo RUN_BACKUP_RESTORE_E2E=1 bash scripts/test-backup-restore.sh
#
# Requires: curl, psql, easy-waf-api, DATABASE_URL in /etc/easy-waf/easy-waf.env,
#           and an admin panel username/password (prompted on a TTY or supplied
#           as EASY_WAF_E2E_USERNAME / EASY_WAF_E2E_PASSWORD).
# Optional: EASY_WAF_E2E_TOTP_CODE, EASY_WAF_API_BASE, EASY_WAF_STATE_DIR,
#           EASY_WAF_API_CA_CERT, EASY_WAF_CURL_INSECURE=1 for an explicit
#           insecure recovery test

set -euo pipefail

if [[ "${RUN_BACKUP_RESTORE_E2E:-}" != "1" ]]; then
  echo "SKIP: set RUN_BACKUP_RESTORE_E2E=1 and run as root (destructive: factory-reset + restore)"
  exit 0
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root (sudo)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
ENV_FILE="${EASY_WAF_ENV_FILE:-/etc/easy-waf/easy-waf.env}"
API_BASE="${EASY_WAF_API_BASE:-https://127.0.0.1:8443}"
BASE="${API_BASE%/}"
API_CA_CERT="${EASY_WAF_API_CA_CERT:-${STATE}/secrets/management.crt}"
ADMIN_BIN="${EASY_WAF_ADMIN_BIN:-/usr/sbin/easy-waf-admin}"
CERT_SRC="${EASY_WAF_E2E_CERT_PEM:-${REPO_ROOT}/internal/haproxy/testdata/golden/certs/bundle-a.pem}"
E2E_TMPDIR="$(mktemp -d)"
BACKUP_PATH="${EASY_WAF_E2E_BACKUP_PATH:-${E2E_TMPDIR}/backup.tar.gz}"
APP_HOST="backup-restore-e2e.example.local"
BACKEND_IP="10.77.88.99"
CERT_ID="e2e-backup-restore-cert"
APP_ID="e2e-backup-restore-app"
BUNDLE_PATH="${STATE}/certs/_e2e/e2e-bundle.pem"
BACKUP_CREATED=0

die() { echo "ERROR: $*" >&2; exit 1; }

cleanup() {
  rm -rf "$E2E_TMPDIR"
  if [[ "$BACKUP_CREATED" == "1" ]]; then
    rm -f "$BACKUP_PATH" 2>/dev/null || true
  fi
}
trap cleanup EXIT

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

command -v curl &>/dev/null || die "curl required"
command -v psql &>/dev/null || die "psql required"
[[ -f "$ENV_FILE" ]] || die "missing $ENV_FILE"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
[[ -n "${DATABASE_URL:-}" ]] || die "DATABASE_URL not set in $ENV_FILE"
[[ ! -e "$BACKUP_PATH" && ! -L "$BACKUP_PATH" ]] \
  || die "refusing to overwrite existing backup path: $BACKUP_PATH"
[[ ! -e "$BUNDLE_PATH" && ! -L "$BUNDLE_PATH" ]] \
  || die "reserved E2E PEM already exists: $BUNDLE_PATH"
reserved_rows="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -Atqc \
  "SELECT (SELECT COUNT(*) FROM applications WHERE id = '$APP_ID') + (SELECT COUNT(*) FROM certificates WHERE id = '$CERT_ID')")" \
  || die "could not check reserved E2E identifiers"
[[ "$reserved_rows" == "0" ]] \
  || die "reserved E2E application or certificate already exists; refusing to overwrite it"

E2E_USERNAME="${EASY_WAF_E2E_USERNAME:-}"
E2E_PASSWORD="${EASY_WAF_E2E_PASSWORD:-}"
E2E_TOTP_CODE="${EASY_WAF_E2E_TOTP_CODE:-}"
if [[ -z "$E2E_USERNAME" || -z "$E2E_PASSWORD" ]]; then
  [[ -t 0 ]] || die "set EASY_WAF_E2E_USERNAME and EASY_WAF_E2E_PASSWORD when stdin is not a TTY"
  if [[ -z "$E2E_USERNAME" ]]; then
    read -r -p "Panel admin username: " E2E_USERNAME
  fi
  if [[ -z "$E2E_PASSWORD" ]]; then
    read -r -s -p "Panel admin password: " E2E_PASSWORD
    echo
  fi
fi
[[ -n "$E2E_USERNAME" && -n "$E2E_PASSWORD" ]] || die "panel username and password are required"

CURL_EXTRA=()
if [[ "$API_BASE" == https://* ]]; then
  if [[ "${EASY_WAF_CURL_INSECURE:-0}" == "1" ]]; then
    CURL_EXTRA=(--insecure)
  elif [[ -f "$API_CA_CERT" ]]; then
    CURL_EXTRA=(--cacert "$API_CA_CERT")
  fi
fi

AUTH_BODY=""
AUTH_CODE=""
auth_json_post() {
  local path="$1" bearer="$2" payload="$3"
  local args=("${CURL_EXTRA[@]}" -sS -o "${E2E_TMPDIR}/auth-response" -w '%{http_code}'
    -X POST "${BASE}${path}"
    -H "Content-Type: application/json"
    -H "X-Requested-With: XMLHttpRequest")
  if [[ -n "$bearer" ]]; then
    args+=(-H "Authorization: Bearer ${bearer}")
  fi
  AUTH_CODE="$(curl "${args[@]}" --data-binary @- <<<"$payload")" || die "request to $path failed"
  AUTH_BODY="$(<"${E2E_TMPDIR}/auth-response")"
}

login_session() {
  local payload
  payload="$(printf '{\"username\":\"%s\",\"password\":\"%s\"' \
    "$(json_escape "$E2E_USERNAME")" "$(json_escape "$E2E_PASSWORD")")"
  if [[ -n "$E2E_TOTP_CODE" ]]; then
    payload+=",\"totp_code\":\"$(json_escape "$E2E_TOTP_CODE")\""
  fi
  payload+='}'
  auth_json_post "/api/v1/auth/login" "" "$payload"
  [[ "$AUTH_CODE" == "200" ]] || die "panel login failed (HTTP $AUTH_CODE): $(head -c 200 <<<"$AUTH_BODY")"
  SESSION_TOKEN="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' <<<"$AUTH_BODY")"
  [[ -n "$SESSION_TOKEN" ]] || die "panel login returned no token"
}

confirm_session() {
  local payload
  payload="$(printf '{\"password\":\"%s\"}' "$(json_escape "$E2E_PASSWORD")")"
  auth_json_post "/api/v1/auth/confirm" "$SESSION_TOKEN" "$payload"
  [[ "$AUTH_CODE" == "200" ]] || die "password confirmation failed (HTTP $AUTH_CODE): $(head -c 200 <<<"$AUTH_BODY")"
  STEP_UP_TOKEN="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' <<<"$AUTH_BODY")"
  [[ -n "$STEP_UP_TOKEN" ]] || die "password confirmation returned no token"
}

api_get() {
  curl -fsS "${CURL_EXTRA[@]}" -H "Authorization: Bearer ${SESSION_TOKEN}" "$1"
}

api_post() {
  curl -fsS "${CURL_EXTRA[@]}" -H "Authorization: Bearer ${STEP_UP_TOKEN}" -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" -X POST "$1" --data-binary @- <<<"$2"
}

api_delete() {
  curl -fsS "${CURL_EXTRA[@]}" -H "Authorization: Bearer ${STEP_UP_TOKEN}" -H "X-Requested-With: XMLHttpRequest" -X DELETE "$1"
}

SESSION_TOKEN=""
STEP_UP_TOKEN=""
login_session
confirm_session

echo "[e2e] prepare PEM under $STATE/certs/_e2e/"
install -d -m0750 -o easy-waf -g easy-waf "${STATE}/certs/_e2e"
if [[ ! -f "$CERT_SRC" ]]; then
  command -v openssl >/dev/null || die "missing cert file: $CERT_SRC (and openssl is not installed)"
  tmp="${E2E_TMPDIR}/cert"
  mkdir -m 700 "$tmp"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -days 3650 \
    -subj "/CN=a.example.com" >/dev/null 2>&1 \
    || die "openssl could not write a test certificate"
  cat "$tmp/cert.pem" "$tmp/key.pem" >"${STATE}/certs/_e2e/e2e-bundle.pem"
  chown easy-waf:easy-waf "${STATE}/certs/_e2e/e2e-bundle.pem"
  chmod 640 "${STATE}/certs/_e2e/e2e-bundle.pem"
else
  install -m0640 -o easy-waf -g easy-waf "$CERT_SRC" "${STATE}/certs/_e2e/e2e-bundle.pem"
fi

CERT_JSON="$(printf '%s' "{\"id\":\"%s\",\"primary_domain\":\"%s\",\"mode\":\"self-signed\",\"pem_crt_path\":\"%s\"}" "$CERT_ID" "$APP_HOST" "$BUNDLE_PATH")"
APP_JSON="$(printf '%s' "{\"id\":\"%s\",\"name\":\"E2E Backup\",\"public_host\":\"%s\",\"backend_host\":\"%s\",\"backend_port\":8080,\"profile\":\"balanced\",\"certificate_id\":\"%s\",\"enabled\":true}" "$APP_ID" "$APP_HOST" "$BACKEND_IP" "$CERT_ID")"

echo "[e2e] upsert certificate + application"
api_post "${BASE}/api/v1/certificates" "$CERT_JSON"
api_post "${BASE}/api/v1/applications" "$APP_JSON"
api_post "${BASE}/api/v1/apply" '{"label":"e2e-before-backup"}'

echo "[e2e] backup → $BACKUP_PATH"
bash "${SCRIPT_DIR}/backup.sh" "$BACKUP_PATH"
BACKUP_CREATED=1

echo "[e2e] stop API, factory reset (DB + state dirs)"
systemctl stop easy-waf-api.service 2>/dev/null || true
systemctl stop easy-waf-acmed.service 2>/dev/null || true
[[ -x "$ADMIN_BIN" ]] || die "missing $ADMIN_BIN"
env DATABASE_URL="$DATABASE_URL" "$ADMIN_BIN" factory-reset -i-am-sure=true -state-dir="$STATE"

echo "[e2e] verify application removed directly in PostgreSQL"
removed_count="$(psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -Atqc \
  "SELECT COUNT(*) FROM applications WHERE id = '$APP_ID'")" \
  || die "could not query applications after factory-reset"
[[ "$removed_count" == "0" ]] || die "expected application $APP_ID to be removed after factory-reset"

echo "[e2e] restore from $BACKUP_PATH"
bash "${SCRIPT_DIR}/restore.sh" "$BACKUP_PATH"

echo "[e2e] verify application restored"
sleep 2
APPS_JSON="$(api_get "${BASE}/api/v1/applications")"
echo "$APPS_JSON" | grep -Fq "\"id\":\"$APP_ID\"" || die "application $APP_ID not found after restore"
echo "$APPS_JSON" | grep -Fq "\"backend_host\":\"$BACKEND_IP\"" || die "backend IP not in applications JSON"

CFG_HA="${STATE}/haproxy/haproxy.cfg"
[[ -f "$CFG_HA" ]] || die "missing $CFG_HA"
grep -q "$BACKEND_IP" "$CFG_HA" || die "haproxy.cfg missing backend IP $BACKEND_IP"

echo "[e2e] remove test rows and re-apply the original edge state"
confirm_session
api_delete "${BASE}/api/v1/applications/${APP_ID}"
api_delete "${BASE}/api/v1/certificates/${CERT_ID}"
api_post "${BASE}/api/v1/apply" '{"label":"e2e-cleanup"}'
rm -f "$BUNDLE_PATH"
rmdir "${STATE}/certs/_e2e" 2>/dev/null || true

echo "[e2e] OK — backup/restore round-trip succeeded"
