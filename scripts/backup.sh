#!/usr/bin/env bash
# Full appliance backup: PostgreSQL custom-format dump + /var/lib/easy-waf + /etc/easy-waf → one .tar.gz
# Run as root (reads /etc, may run pg_dump). See docs/BACKUP_RESTORE.md
#
# Usage: sudo bash scripts/backup.sh [output.tar.gz]
# Env: EASY_WAF_STATE_DIR (default /var/lib/easy-waf)
#      EASY_WAF_ENV_FILE  (default /etc/easy-waf/easy-waf.env) — for DATABASE_URL

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh"

STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
CFG="/etc/easy-waf"
ENV_FILE="${EASY_WAF_ENV_FILE:-${CFG}/easy-waf.env}"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEFAULT_NAME="easy-waf-backup-${STAMP}.tar.gz"
OUT="${1:-$DEFAULT_NAME}"
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

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-backup.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

TOP="easy-waf-backup-${STAMP}"
ROOT="$WORKDIR/$TOP"
mkdir -p "$ROOT/state" "$ROOT/etc"

{
  echo "easy-waf-backup-format v1"
  echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "state_dir=$STATE"
  echo "config_dir=$CFG"
} >"$ROOT/MANIFEST.txt"

if ! command -v pg_dump &>/dev/null; then
  echo "ERROR: pg_dump not found (install postgresql client packages)" >&2
  exit 1
fi

echo "[easy-waf-backup] pg_dump (custom format) → $ROOT/easywaf.dump"
pg_dump "$DATABASE_URL" --format=custom --file="$ROOT/easywaf.dump"

echo "[easy-waf-backup] archiving state: $STATE"
tar -C "$STATE" -cf - . | tar -C "$ROOT/state" -xf -

echo "[easy-waf-backup] archiving: $CFG"
tar -C "$CFG" -cf - . | tar -C "$ROOT/etc" -xf -

mkdir -p "$(dirname "$OUT")"
echo "[easy-waf-backup] packing → $OUT"
tar -czf "$OUT" -C "$WORKDIR" "$TOP"
chmod 0600 "$OUT"

SIZE="$(du -h "$OUT" | awk '{print $1}')"
echo "[easy-waf-backup] done: $OUT (size $SIZE)"
