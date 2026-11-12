#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/backup-rotate.sh
source "${SCRIPT_DIR}/lib/backup-rotate.sh"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-rotate-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

for s in 20260101-033000 20260102-033000 20260103-033000 20260104-033000; do
  : >"$TMP/easy-waf-backup-${s}.tar.gz"
done
: >"$TMP/easy-waf-backup-20260105-033000.tar.gz.partial"
: >"$TMP/easy-waf-backup-manual.tar.gz"
: >"$TMP/notes.txt"

easy_waf_rotate_backups "$TMP" 2 >/dev/null
[[ ! -e "$TMP/easy-waf-backup-20260101-033000.tar.gz" ]]
[[ ! -e "$TMP/easy-waf-backup-20260102-033000.tar.gz" ]]
[[ -e "$TMP/easy-waf-backup-20260103-033000.tar.gz" ]]
[[ -e "$TMP/easy-waf-backup-20260104-033000.tar.gz" ]]
[[ -e "$TMP/easy-waf-backup-20260105-033000.tar.gz.partial" ]]
[[ -e "$TMP/easy-waf-backup-manual.tar.gz" ]]
[[ -e "$TMP/notes.txt" ]]

easy_waf_rotate_backups "$TMP" 0 >/dev/null
[[ -e "$TMP/easy-waf-backup-20260103-033000.tar.gz" ]]
if easy_waf_rotate_backups "$TMP" abc 2>/dev/null; then
  echo "non-numeric keep accepted" >&2
  exit 1
fi

# Argument errors are reported before the root check.
if "${BASH}" "${SCRIPT_DIR}/backup.sh" --keep 3 2>/dev/null; then
  echo "--keep without --dir accepted" >&2
  exit 1
fi
if "${BASH}" "${SCRIPT_DIR}/backup.sh" --dir "$TMP" out.tar.gz 2>/dev/null; then
  echo "--dir with an output path accepted" >&2
  exit 1
fi

echo "backup rotation: OK"
