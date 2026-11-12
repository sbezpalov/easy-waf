#!/usr/bin/env bash
# Full appliance backup: PostgreSQL custom-format dump + /var/lib/easy-waf + /etc/easy-waf → one .tar.gz
# Run as root (reads /etc, may run pg_dump). See docs/BACKUP_RESTORE.md
#
# Usage: sudo bash scripts/backup.sh [output.tar.gz]
#        sudo easy-waf-backup --dir /var/backups/easy-waf --keep 7
#          (writes easy-waf-backup-<timestamp>.tar.gz into the directory, then
#           deletes all but the 7 newest; what easy-waf-backup.timer runs daily)
# Env: EASY_WAF_STATE_DIR (default /var/lib/easy-waf)
#      EASY_WAF_ENV_FILE  (default /etc/easy-waf/easy-waf.env) — for DATABASE_URL

set -euo pipefail
umask 077

# readlink: the package links /usr/sbin/easy-waf-backup to this file.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh"
# shellcheck source=lib/backup-rotate.sh
source "${SCRIPT_DIR}/lib/backup-rotate.sh"

STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
CFG="/etc/easy-waf"
ENV_FILE="${EASY_WAF_ENV_FILE:-${CFG}/easy-waf.env}"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEFAULT_NAME="easy-waf-backup-${STAMP}.tar.gz"
DIR=""
KEEP=0
OUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      DIR="${2:-}"
      [[ -n "$DIR" ]] || { echo "ERROR: --dir needs a path" >&2; exit 2; }
      shift 2
      ;;
    --keep)
      KEEP="${2:-}"
      shift 2 || { echo "ERROR: --keep needs a number" >&2; exit 2; }
      ;;
    -*)
      echo "ERROR: unknown option: $1" >&2
      exit 2
      ;;
    *)
      [[ -z "$OUT" ]] || { echo "ERROR: more than one output path" >&2; exit 2; }
      OUT="$1"
      shift
      ;;
  esac
done
if [[ ! "$KEEP" =~ ^[0-9]+$ ]]; then
  echo "ERROR: --keep must be a whole number" >&2
  exit 2
fi
if [[ -n "$DIR" && -n "$OUT" ]]; then
  echo "ERROR: give either --dir or an output path, not both" >&2
  exit 2
fi
if [[ "$KEEP" -gt 0 && -z "$DIR" ]]; then
  echo "ERROR: --keep needs --dir" >&2
  exit 2
fi
if [[ -n "$DIR" ]]; then
  OUT="${DIR%/}/${DEFAULT_NAME}"
fi
OUT="${OUT:-$DEFAULT_NAME}"
if [[ "$OUT" != /* ]]; then
  OUT="$(pwd)/${OUT#./}"
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash $0 $*" >&2
  exit 1
fi

if [[ ! -d "$STATE" ]]; then
  echo "ERROR: state dir missing: $STATE" >&2
  exit 1
fi
if [[ ! -d "$CFG" ]]; then
  echo "ERROR: config dir missing: $CFG" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file missing: $ENV_FILE (set EASY_WAF_ENV_FILE?)" >&2
  exit 1
fi

DATABASE_URL="$(easy_waf_read_env_value "$ENV_FILE" DATABASE_URL)"
export DATABASE_URL
if [[ -z "$DATABASE_URL" ]]; then
  echo "ERROR: DATABASE_URL not set in $ENV_FILE" >&2
  exit 1
fi

if [[ -n "$DIR" && ! -d "$DIR" ]]; then
  install -d -m 0700 "$DIR"
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-backup.XXXXXX")"
# Track which writers we stopped so cleanup can restart them even on failure.
BACKUP_STOPPED_UNITS=()
# A failed run leaves no truncated archive for rotation to count.
cleanup() {
  local u
  for u in "${BACKUP_STOPPED_UNITS[@]}"; do
    systemctl start "$u" 2>/dev/null || true
  done
  rm -rf "$WORKDIR"
  rm -f "${OUT}.partial"
}
trap cleanup EXIT

TOP="easy-waf-backup-${STAMP}"
ROOT="$WORKDIR/$TOP"
mkdir -p "$ROOT/state" "$ROOT/etc"

{
  echo "easy-waf-backup-format v1"
  echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "state_dir=$STATE"
  echo "config_dir=$CFG"
  echo "quiesced=easy-waf-api,easy-waf-acmed"
} >"$ROOT/MANIFEST.txt"

if ! command -v pg_dump &>/dev/null; then
  echo "ERROR: pg_dump not found (install postgresql client packages)" >&2
  exit 1
fi

# Quiesce control-plane writers so pg_dump and on-disk secrets/certs stay
# consistent. Without this, ACME/apply/rotation between steps can pair a dump
# with PEMs/env that do not match. Edge (HAProxy) keeps serving.
echo "[easy-waf-backup] quiescing writers (easy-waf-api, easy-waf-acmed)…"
for u in easy-waf-api.service easy-waf-acmed.service; do
  if systemctl is-active --quiet "$u" 2>/dev/null; then
    # Record before stop so cleanup restarts even if stop/dump fails mid-way.
    BACKUP_STOPPED_UNITS+=("$u")
    systemctl stop "$u"
  fi
done

echo "[easy-waf-backup] pg_dump (custom format) → $ROOT/easywaf.dump"
pg_dump "$DATABASE_URL" --format=custom --file="$ROOT/easywaf.dump"

echo "[easy-waf-backup] archiving state: $STATE"
tar -C "$STATE" -cf - . | tar -C "$ROOT/state" -xf -

echo "[easy-waf-backup] archiving: $CFG"
tar -C "$CFG" -cf - . | tar -C "$ROOT/etc" -xf -

mkdir -p "$(dirname "$OUT")"
echo "[easy-waf-backup] packing → $OUT"
tar -czf "${OUT}.partial" -C "$WORKDIR" "$TOP"
chmod 0600 "${OUT}.partial"
mv -f "${OUT}.partial" "$OUT"

SIZE="$(du -h "$OUT" | awk '{print $1}')"
echo "[easy-waf-backup] done: $OUT (size $SIZE)"

if [[ -n "$DIR" ]]; then
  easy_waf_rotate_backups "$DIR" "$KEEP"
fi
