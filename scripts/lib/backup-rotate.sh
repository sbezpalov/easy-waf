#!/usr/bin/env bash

# easy_waf_rotate_backups DIR KEEP — delete all but the KEEP newest
# easy-waf-backup-<YYYYMMDD-HHMMSS>.tar.gz archives in DIR. The timestamp makes
# name order age order. KEEP=0 keeps everything. Other files are never touched.
easy_waf_rotate_backups() {
  local dir="$1" keep="$2" f n
  if [[ ! "$keep" =~ ^[0-9]+$ ]]; then
    echo "[easy-waf-backup] keep must be a whole number, got: $keep" >&2
    return 1
  fi
  (( keep > 0 )) || return 0
  local -a files=()
  local restore_nullglob
  restore_nullglob="$(shopt -p nullglob || true)"
  shopt -s nullglob
  files=("$dir"/easy-waf-backup-[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9][0-9][0-9].tar.gz)
  eval "$restore_nullglob"
  (( ${#files[@]} > keep )) || return 0
  n=$(( ${#files[@]} - keep ))
  for f in "${files[@]:0:n}"; do
    rm -f -- "$f"
    echo "[easy-waf-backup] rotated out: $f"
  done
}
