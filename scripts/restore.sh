#!/usr/bin/env bash
# Restore from backup produced by scripts/backup.sh (format v1).
# Run as root. Stops the control plane, restores DB + files, optionally applies
# the edge from the console, then starts services.
#
# Usage: sudo bash scripts/restore.sh /path/to/easy-waf-backup-YYYYMMDD-HHMMSS.tar.gz
# Env: EASY_WAF_STATE_DIR, EASY_WAF_ENV_FILE (defaults as in backup.sh)
#      EASY_WAF_ADMIN_BIN — default /usr/sbin/easy-waf-admin
#      EASY_WAF_SKIP_APPLY=1 — do not run easy-waf-admin apply-edge

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh"

ARCHIVE="${1:?usage: sudo bash scripts/restore.sh /path/to/easy-waf-backup-*.tar.gz}"
if [[ "$ARCHIVE" != /* ]]; then
  ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"
fi
STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
CFG="/etc/easy-waf"
ENV_FILE="${EASY_WAF_ENV_FILE:-${CFG}/easy-waf.env}"
ADMIN_BIN="${EASY_WAF_ADMIN_BIN:-/usr/sbin/easy-waf-admin}"

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
# The archive is operator-supplied and this runs as root: refuse absolute paths
# and ".." members, and never restore the archive's own uid/gid.
#
# The listing is materialised and matched with a here-string, never through a
# pipe. Under `set -o pipefail`, `tar … | grep -q` made this guard fail *open*:
# grep exits at the first match, the writer dies of SIGPIPE, the pipeline reports
# failure, the `if` is false, and the malicious archive is extracted. Verified
# against an archive whose first member is "../escaped" followed by enough
# padding to keep tar writing. A here-string keeps the producer out of
# PIPESTATUS, so only grep's own result decides.
archive_members="$(tar -tzf "$ARCHIVE")"
if grep -qE '^/|(^|/)\.\.(/|$)' <<<"$archive_members"; then
  echo "ERROR: archive contains absolute or parent-relative paths — refusing to extract" >&2
  exit 1
fi
unset archive_members
tar --no-same-owner --no-same-permissions -xzf "$ARCHIVE" -C "$WORKDIR"

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

echo "[easy-waf-restore] stopping control plane and host broker (if running)…"
systemctl stop easy-waf-api.service 2>/dev/null || true
systemctl stop easy-waf-acmed.service 2>/dev/null || true
systemctl stop easy-waf-hostd.service 2>/dev/null || true

REST_ENV="$ROOT/etc/easy-waf.env"
if [[ ! -f "$REST_ENV" ]]; then
  echo "ERROR: backup missing etc/easy-waf.env" >&2
  exit 1
fi

DATABASE_URL="$(easy_waf_read_env_value "$REST_ENV" DATABASE_URL)"
export DATABASE_URL
if [[ -z "$DATABASE_URL" ]]; then
  echo "ERROR: DATABASE_URL empty in backup env $REST_ENV" >&2
  exit 1
fi

echo "[easy-waf-restore] pg_restore into configured database (single transaction; drops conflicting objects)…"
# --single-transaction keeps --clean + restore atomic: a mid-restore failure
# rolls back instead of leaving a half-destroyed schema with the control plane down.
if ! pg_restore --single-transaction --clean --if-exists --no-owner --no-acl -d "$DATABASE_URL" "$ROOT/easywaf.dump"; then
  echo "ERROR: pg_restore failed — database left unchanged; refusing to replace on-disk state" >&2
  exit 1
fi

mkdir -p "$STATE" "$CFG"
# Wipe then replace: extract-over-existing left orphan PEMs, edge tokens, DNS
# env, rollback/staging and mixed old secrets with the restored DB.
echo "[easy-waf-restore] wiping $STATE before restore (replace, not merge)…"
find "$STATE" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
echo "[easy-waf-restore] restoring $STATE from backup…"
tar -C "$ROOT/state" -cf - . | tar --no-same-owner -C "$STATE" -xf -
# The backup's record of which certificates HAProxy had loaded describes the
# backed-up appliance, not the HAProxy running now. Without it the API's
# startup reconcile re-applies, so the restored certificates are loaded even
# when the console apply below is skipped.
rm -f "$STATE/haproxy/.loaded-certs.json"

echo "[easy-waf-restore] wiping $CFG before restore (replace, not merge)…"
find "$CFG" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
echo "[easy-waf-restore] restoring $CFG from backup…"
tar -C "$ROOT/etc" -cf - . | tar --no-same-owner -C "$CFG" -xf -

chown -R easy-waf:easy-waf "$STATE" 2>/dev/null || true
find "$CFG" -type d -exec chmod 0750 {} + 2>/dev/null || true
find "$CFG" -type f -exec chmod 0640 {} + 2>/dev/null || true
chown -R root:easy-waf "$CFG" 2>/dev/null || true
# Secrets must not stay readable by group easy-waf, which includes haproxy.
# DNS credential files are opened by easy-waf-acmed itself, so that account owns them.
find "$CFG" -type f -name '*.env' -exec chown easy-waf:easy-waf {} + 2>/dev/null || true
find "$CFG" -type f -name '*.env' -exec chmod 0600 {} + 2>/dev/null || true
if [[ -f "$CFG/easy-waf.env" ]]; then
  easy_waf_secure_env_file "$CFG/easy-waf.env"
fi

if command -v restorecon &>/dev/null; then
  echo "[easy-waf-restore] restorecon (legacy SELinux hosts only)…"
  restorecon -RF "$STATE" 2>/dev/null || true
  restorecon -RF "$CFG" 2>/dev/null || true
fi

if command -v semanage &>/dev/null && [[ -f "${SCRIPT_DIR}/lib/selinux-easy-waf-haproxy.sh" ]]; then
  EASY_WAF_STATE_DIR="$STATE" bash "${SCRIPT_DIR}/lib/selinux-easy-waf-haproxy.sh" 2>/dev/null || true
fi

if [[ "${EASY_WAF_SKIP_APPLY:-0}" == "1" ]]; then
  echo "[easy-waf-restore] EASY_WAF_SKIP_APPLY=1 — skipping console apply"
elif [[ ! -x "$ADMIN_BIN" ]]; then
  echo "WARNING: $ADMIN_BIN not found — run easy-waf-admin apply-edge after installing the package" >&2
else
  echo "[easy-waf-restore] easy-waf-admin apply-edge (regenerate HAProxy)…"
  if "$ADMIN_BIN" apply-edge -env-file "$ENV_FILE" -state-dir "$STATE" -label restore; then
    echo "[easy-waf-restore] apply OK"
  else
    echo "WARNING: apply-edge failed — run it manually after fixing the reported problem" >&2
  fi
fi

echo "[easy-waf-restore] starting services…"
systemctl daemon-reload 2>/dev/null || true
systemctl start easy-waf-hostd.service 2>/dev/null || true
systemctl start easy-waf-api.service 2>/dev/null || {
  echo "WARNING: easy-waf-api failed to start — check journalctl -u easy-waf-api" >&2
}
systemctl start easy-waf-acmed.service 2>/dev/null || true

echo "[easy-waf-restore] done. Validate: haproxy -c -f $STATE/haproxy/haproxy.cfg (path may differ via settings)"
