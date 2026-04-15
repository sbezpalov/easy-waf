#!/usr/bin/env bash
# End-to-end backup / factory-reset / restore check (appliance with easy-waf-api).
#
#   sudo RUN_BACKUP_RESTORE_E2E=1 bash scripts/test-backup-restore.sh
#
# Requires: curl, easy-waf-api, DATABASE_URL + EASY_WAF_ADMIN_TOKEN in /etc/easy-waf/easy-waf.env
# Optional: EASY_WAF_API_BASE, EASY_WAF_STATE_DIR, EASY_WAF_CURL_INSECURE=1 for https self-signed

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
API_BASE="${EASY_WAF_API_BASE:-http://127.0.0.1:8000}"
BASE="${API_BASE%/}"
ADMIN_BIN="${EASY_WAF_ADMIN_BIN:-/usr/sbin/easy-waf-admin}"
CERT_SRC="${EASY_WAF_E2E_CERT_PEM:-${REPO_ROOT}/internal/haproxy/testdata/golden/certs/bundle-a.pem}"
BACKUP_PATH="${EASY_WAF_E2E_BACKUP_PATH:-/tmp/easy-waf-e2e-backup-$$.tar.gz}"
APP_HOST="backup-restore-e2e.example.local"
BACKEND_IP="10.77.88.99"
CERT_ID="e2e-backup-restore-cert"
APP_ID="e2e-backup-restore-app"

die() { echo "ERROR: $*" >&2; exit 1; }

command -v curl &>/dev/null || die "curl required"
[[ -f "$ENV_FILE" ]] || die "missing $ENV_FILE"
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
[[ -n "${DATABASE_URL:-}" ]] || die "DATABASE_URL not set in $ENV_FILE"
[[ -n "${EASY_WAF_ADMIN_TOKEN:-}" ]] || die "EASY_WAF_ADMIN_TOKEN not set in $ENV_FILE (needed for API apply)"

CURL_EXTRA=()
[[ "${EASY_WAF_CURL_INSECURE:-0}" == "1" ]] && CURL_EXTRA=( -k )

api_get() {
  curl -fsS "${CURL_EXTRA[@]}" -H "Authorization: Bearer ${EASY_WAF_ADMIN_TOKEN}" "$1"
}

api_post() {
  curl -fsS "${CURL_EXTRA[@]}" -H "Authorization: Bearer ${EASY_WAF_ADMIN_TOKEN}" -H "Content-Type: application/json" -X POST "$1" -d "$2"
}

echo "[e2e] prepare PEM under $STATE/certs/_e2e/"
install -d -m0750 -o easy-waf -g easy-waf "${STATE}/certs/_e2e"
[[ -f "$CERT_SRC" ]] || die "missing cert file: $CERT_SRC"
install -m0640 -o easy-waf -g easy-waf "$CERT_SRC" "${STATE}/certs/_e2e/e2e-bundle.pem"

BUNDLE_PATH="${STATE}/certs/_e2e/e2e-bundle.pem"
CERT_JSON="$(printf '%s' "{\"id\":\"%s\",\"primary_domain\":\"%s\",\"mode\":\"self-signed\",\"pem_crt_path\":\"%s\"}" "$CERT_ID" "$APP_HOST" "$BUNDLE_PATH")"
APP_JSON="$(printf '%s' "{\"id\":\"%s\",\"name\":\"E2E Backup\",\"public_host\":\"%s\",\"backend_host\":\"%s\",\"backend_port\":8080,\"profile\":\"balanced\",\"certificate_id\":\"%s\",\"enabled\":true}" "$APP_ID" "$APP_HOST" "$BACKEND_IP" "$CERT_ID")"

echo "[e2e] upsert certificate + application"
api_post "${BASE}/api/v1/certificates" "$CERT_JSON"
api_post "${BASE}/api/v1/applications" "$APP_JSON"
api_post "${BASE}/api/v1/apply" '{"label":"e2e-before-backup"}'

echo "[e2e] backup → $BACKUP_PATH"
bash "${SCRIPT_DIR}/backup.sh" "$BACKUP_PATH"

echo "[e2e] stop API, factory reset (DB + state dirs)"
systemctl stop easy-waf-api.service 2>/dev/null || true
systemctl stop easy-waf-acmed.service 2>/dev/null || true
[[ -x "$ADMIN_BIN" ]] || die "missing $ADMIN_BIN"
env DATABASE_URL="$DATABASE_URL" "$ADMIN_BIN" factory-reset -i-am-sure=true -state-dir="$STATE"

echo "[e2e] start API and verify application removed"
systemctl start easy-waf-api.service 2>/dev/null || die "easy-waf-api failed to start"
sleep 2
if api_get "${BASE}/api/v1/applications" | grep -Fq "\"id\":\"$APP_ID\""; then
  die "expected application $APP_ID to be removed after factory-reset"
fi

echo "[e2e] restore from $BACKUP_PATH"
export EASY_WAF_ADMIN_TOKEN
bash "${SCRIPT_DIR}/restore.sh" "$BACKUP_PATH"

echo "[e2e] verify application restored"
sleep 2
APPS_JSON="$(api_get "${BASE}/api/v1/applications")"
echo "$APPS_JSON" | grep -Fq "\"id\":\"$APP_ID\"" || die "application $APP_ID not found after restore"
echo "$APPS_JSON" | grep -Fq "\"backend_host\":\"$BACKEND_IP\"" || die "backend IP not in applications JSON"

CFG_HA="${STATE}/haproxy/haproxy.cfg"
[[ -f "$CFG_HA" ]] || die "missing $CFG_HA"
grep -q "$BACKEND_IP" "$CFG_HA" || die "haproxy.cfg missing backend IP $BACKEND_IP"

echo "[e2e] OK — backup/restore round-trip succeeded"
rm -f "$BACKUP_PATH" 2>/dev/null || true
