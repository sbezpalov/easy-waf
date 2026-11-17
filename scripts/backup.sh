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
if ! command -v flock &>/dev/null; then
  echo "ERROR: flock not found (install util-linux)" >&2
  exit 1
fi
# All outputs/state paths share these writer services. Lock the fixed config
# directory inode, without a writable lockfile or stale marker to remove.
# Keep this descriptor open through rotation and EXIT's writer restart.
exec {BACKUP_LOCK_FD}<"$CFG"
if ! flock -n "$BACKUP_LOCK_FD"; then
  echo "ERROR: cannot acquire backup lock; another backup or restore may be running" >&2
  exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: env file missing: $ENV_FILE (set EASY_WAF_ENV_FILE?)" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-backup.XXXXXX")"
OUTPUT_WORKDIR=""
BACKUP_PUBLISHED=0
# Track which writers we stopped so cleanup can restart them even on failure.
BACKUP_STOPPED_UNITS=()
# A failed run leaves no truncated archive for rotation to count.
cleanup() {
  local result=$? u restart_failed=0
  for u in "${BACKUP_STOPPED_UNITS[@]}"; do
    if ! systemctl start "$u"; then
      echo "ERROR: could not resume $u — check journalctl -u $u" >&2
      restart_failed=1
    fi
  done
  rm -rf "$WORKDIR"
  if [[ -n "$OUTPUT_WORKDIR" ]]; then
    rm -rf "$OUTPUT_WORKDIR"
  fi
  if ((restart_failed)); then
    if ((BACKUP_PUBLISHED)); then
      echo "ERROR: backup archive saved at $OUT, but writer recovery is incomplete" >&2
    fi
    if ((result == 0)); then result=1; fi
  elif ((result == 0 && BACKUP_PUBLISHED)); then
    echo "[easy-waf-backup] done: $OUT (size $SIZE)"
  fi
  exit "$result"
}
trap cleanup EXIT

TOP="easy-waf-backup-${STAMP}"
ROOT="$WORKDIR/$TOP"
mkdir -p "$ROOT/state" "$ROOT/etc"

# Pin the exact configuration used by this dump before stopping any writers.
# An alternate source selects only DATABASE_URL. Retain the other settings
# from the canonical appliance file.
archived_env="$ROOT/etc/easy-waf.env"
canonical_env="$CFG/easy-waf.env"
if [[ -f "$canonical_env" ]]; then
  install -m 0600 -- "$canonical_env" "$archived_env"
elif [[ -e "$canonical_env" || -L "$canonical_env" ]]; then
  echo "ERROR: not a regular config file: $canonical_env" >&2
  exit 1
else
  : >"$archived_env"
fi
if [[ ! "$ENV_FILE" -ef "$canonical_env" ]]; then
  assignment="$(easy_waf_read_env_assignment "$ENV_FILE" DATABASE_URL)"
  sed -i '/^[[:blank:]]*DATABASE_URL[[:blank:]]*=/d' "$archived_env"
  printf '\n%s\n' "$assignment" >>"$archived_env"
fi
DATABASE_URL="$(easy_waf_read_env_value "$archived_env" DATABASE_URL)"
if [[ -z "$DATABASE_URL" ]]; then
  echo "ERROR: DATABASE_URL not set in $ENV_FILE" >&2
  exit 1
fi
if [[ -n "$DIR" && ! -d "$DIR" ]]; then
  install -d -m 0700 "$DIR"
fi

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
if ! command -v python3 &>/dev/null || [[ ! -r "$SCRIPT_DIR/lib/pg-archive.py" ]]; then
  echo "ERROR: Python 3 or the PostgreSQL archive helper is missing" >&2
  exit 1
fi

# Quiesce control-plane writers so pg_dump and on-disk secrets/certs stay
# consistent. Without this, ACME/apply/rotation between steps can pair a dump
# with PEMs/env that do not match. Edge (HAProxy) keeps serving.
echo "[easy-waf-backup] quiescing writers (easy-waf-api, easy-waf-acmed)…"
writers=(easy-waf-api.service easy-waf-acmed.service)
declare -A initial_states=()
for u in "${writers[@]}"; do
  if ! state="$(systemctl show --property=ActiveState --value "$u")"; then
    echo "ERROR: cannot determine initial state of $u — backup aborted before pg_dump" >&2
    exit 1
  fi
  case "$state" in
    active|activating|reloading|refreshing|deactivating|inactive|failed) initial_states[$u]="$state" ;;
    *)
      echo "ERROR: unexpected state for $u — backup aborted before pg_dump" >&2
      exit 1
      ;;
  esac
done
for u in "${writers[@]}"; do
  case "${initial_states[$u]}" in
    inactive|failed) continue ;;
    deactivating) ;;
    *) BACKUP_STOPPED_UNITS+=("$u") ;;
  esac
  if ! systemctl stop "$u"; then
    echo "ERROR: failed to stop $u — backup aborted before pg_dump" >&2
    exit 1
  fi
done
for u in "${writers[@]}"; do
  if ! state="$(systemctl show --property=ActiveState --value "$u")" ||
    [[ "$state" != inactive && "$state" != failed ]]; then
    echo "ERROR: cannot confirm $u is stopped — backup aborted before pg_dump" >&2
    exit 1
  fi
done

echo "[easy-waf-backup] pg_dump (custom format) → $ROOT/easywaf.dump"
python3 -I "$SCRIPT_DIR/lib/pg-archive.py" "$WORKDIR" pg_dump \
  --format=custom --file="$ROOT/easywaf.dump" <<<"$DATABASE_URL"

echo "[easy-waf-backup] archiving state: $STATE"
tar -C "$STATE" -cf - . | tar -C "$ROOT/state" -xf -

echo "[easy-waf-backup] archiving: $CFG"
# Preserve the pinned env above. Recovery candidates belong to the interrupted
# installer operation rather than the running configuration.
tar --anchored --no-wildcards-match-slash \
  --exclude='./easy-waf.env' \
  --exclude='./easy-waf.env.rotation.??????' --exclude='./easy-waf.env.new-db-password' \
  -C "$CFG" -cf - . | tar -C "$ROOT/etc" -xf -

mkdir -p "$(dirname "$OUT")"
echo "[easy-waf-backup] packing → $OUT"
# Own the staging path, on the output filesystem; never follow a preexisting
# .partial link or remove another run's files. Replace the final pathname only.
OUTPUT_WORKDIR="$(mktemp -d "$(dirname "$OUT")/.easy-waf-backup.XXXXXX")"
ARCHIVE="$OUTPUT_WORKDIR/bundle.tar.gz"
: >"$ARCHIVE"
tar -czf "$ARCHIVE" -C "$WORKDIR" "$TOP"
chmod 0600 "$ARCHIVE"
mv -fT -- "$ARCHIVE" "$OUT"
BACKUP_PUBLISHED=1

SIZE="$(du -h "$OUT" | awk '{print $1}')"

if [[ -n "$DIR" ]]; then
  easy_waf_rotate_backups "$DIR" "$KEEP"
fi
