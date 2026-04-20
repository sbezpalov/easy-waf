#!/usr/bin/env bash
# Restore from backup produced by scripts/backup.sh (format v1).
# Run as root. Stops API, restores DB + files, SELinux restorecon, optional Apply + service restart.
#
# Usage: sudo bash scripts/restore.sh /path/to/easy-waf-backup-YYYYMMDD-HHMMSS.tar.gz
# Env: EASY_WAF_STATE_DIR, EASY_WAF_ENV_FILE (defaults as in backup.sh)
#      EASY_WAF_API_BASE — default http://127.0.0.1:8000 (for POST /api/v1/apply after restore)
#      EASY_WAF_SKIP_APPLY=1 — do not call API apply (regenerate HAProxy yourself)
#      EASY_WAF_ADMIN_TOKEN — if unset, read from restored / merged env after file copy (see below)

set -euo pipefail

ARCHIVE="${1:?usage: sudo bash scripts/restore.sh /path/to/easy-waf-backup-*.tar.gz}"
if [[ "$ARCHIVE" != /* ]]; then
  ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"
fi
STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
CFG="/etc/easy-waf"
ENV_FILE="${EASY_WAF_ENV_FILE:-${CFG}/easy-waf.env}"
API_BASE="${EASY_WAF_API_BASE:-http://127.0.0.1:8000}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash $0 $ARCHIVE" >&2
  exit 1
fi
if [[ ! -f "$ARCHIVE" ]]; then
  echo "ERROR: archive not found: $ARCHIVE" >&2
  exit 1
fi
if ! command -v pg_restore &>/dev/null; then
  echo "ERROR: pg_restore not found" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-restore.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "[easy-waf-restore] extracting archive…"
tar -xzf "$ARCHIVE" -C "$WORKDIR"

ROOT="$(find "$WORKDIR" -mindepth 1 -maxdepth 1 -type d | head -1 || true)"
if [[ -z "$ROOT" ]] || [[ ! -d "$ROOT" ]]; then
  echo "ERROR: could not locate backup root inside archive (expected easy-waf-backup-*/ with MANIFEST.txt)" >&2
  exit 1
fi
if [[ ! -f "$ROOT/easywaf.dump" ]]; then
  echo "ERROR: missing easywaf.dump under $ROOT" >&2
  exit 1
fi
if [[ ! -d "$ROOT/state" ]] || [[ ! -d "$ROOT/etc" ]]; then
  echo "ERROR: backup must contain state/ and etc/ directories (format v1)" >&2
  exit 1
fi

echo "[easy-waf-restore] stopping control plane (if running)…"
systemctl stop easy-waf-api.service 2>/dev/null || true
systemctl stop easy-waf-acmed.service 2>/dev/null || true

REST_ENV="$ROOT/etc/easy-waf.env"
if [[ ! -f "$REST_ENV" ]]; then
  echo "ERROR: backup missing etc/easy-waf.env" >&2
  exit 1
fi

# shellcheck disable=SC1090
set -a
source "$REST_ENV"
set +a
if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "ERROR: DATABASE_URL empty in backup env $REST_ENV" >&2
  exit 1
fi

echo "[easy-waf-restore] pg_restore into configured database (drops conflicting objects)…"
pg_restore --clean --if-exists --no-owner --no-acl -d "$DATABASE_URL" "$ROOT/easywaf.dump"

mkdir -p "$STATE" "$CFG"
echo "[easy-waf-restore] restoring $STATE from backup…"
tar -C "$ROOT/state" -cf - . | tar -C "$STATE" -xf -

echo "[easy-waf-restore] restoring $CFG from backup…"
tar -C "$ROOT/etc" -cf - . | tar -C "$CFG" -xf -

chown -R easy-waf:easy-waf "$STATE" 2>/dev/null || true
find "$CFG" -type d -exec chmod 0750 {} + 2>/dev/null || true
find "$CFG" -type f -exec chmod 0640 {} + 2>/dev/null || true
chown -R root:easy-waf "$CFG" 2>/dev/null || true

if command -v restorecon &>/dev/null; then
  echo "[easy-waf-restore] restorecon (SELinux)…"
  restorecon -RF "$STATE" 2>/dev/null || true
  restorecon -RF "$CFG" 2>/dev/null || true
fi

REST_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${REST_SCRIPT_DIR}/lib/selinux-easy-waf-haproxy.sh" ]]; then
  EASY_WAF_STATE_DIR="$STATE" bash "${REST_SCRIPT_DIR}/lib/selinux-easy-waf-haproxy.sh" 2>/dev/null || true
fi

# Re-read env from disk (restored tokens / URLs)
# shellcheck disable=SC1090
set -a
source "$ENV_FILE"
set +a

echo "[easy-waf-restore] starting services…"
systemctl daemon-reload 2>/dev/null || true
systemctl start easy-waf-api.service 2>/dev/null || {
  echo "WARNING: easy-waf-api failed to start — check journalctl -u easy-waf-api" >&2
}
systemctl start easy-waf-acmed.service 2>/dev/null || true

sleep 2

TOK="${EASY_WAF_ADMIN_TOKEN:-}"
if [[ -z "$TOK" ]]; then
  echo "[easy-waf-restore] EASY_WAF_ADMIN_TOKEN unset — cannot POST apply (set env or add token to $ENV_FILE)" >&2
elif [[ "${EASY_WAF_SKIP_APPLY:-0}" == "1" ]]; then
  echo "[easy-waf-restore] EASY_WAF_SKIP_APPLY=1 — skipping API apply"
else
  echo "[easy-waf-restore] POST $API_BASE/api/v1/apply (regenerate HAProxy)…"
  if curl -fsS -o /dev/null -X POST "${API_BASE%/}/api/v1/apply" \
    -H "Authorization: Bearer ${TOK}" \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    -d '{"label":"restore"}' 2>/dev/null; then
    echo "[easy-waf-restore] apply OK"
  else
    echo "WARNING: apply request failed — run manually: curl -X POST .../api/v1/apply with Bearer token" >&2
  fi
fi

systemctl restart easy-waf-api.service 2>/dev/null || true
systemctl restart easy-waf-acmed.service 2>/dev/null || true
echo "[easy-waf-restore] done. Validate: haproxy -c -f $STATE/haproxy/haproxy.cfg (path may differ via settings)"
