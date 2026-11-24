#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
# Real backup/restore and flock; fake DB/services, private container config only.
set -euo pipefail
awk '$2 == "/etc/easy-waf" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts || exit 90
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_SCRIPT="${EASY_WAF_TEST_BACKUP_SCRIPT:-$SCRIPT_DIR/backup.sh}"
RESTORE_SCRIPT="${EASY_WAF_TEST_RESTORE_SCRIPT:-$SCRIPT_DIR/restore.sh}"
ROOT="$(mktemp -d)"
HOLDER_PID=''
cleanup() {
  touch "$ROOT/release"
  if [[ -n "$HOLDER_PID" ]]; then wait "$HOLDER_PID" || true; fi
  rm -rf "$ROOT"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mode="${1:-all}"
[[ "$mode" == all || "$mode" == preflight || "$mode" == locks ]] || fail 'unknown test selection'
mkdir -p "$ROOT/bin" "$ROOT/source/backup/state" "$ROOT/source/backup/etc" "$ROOT/state"
printf 'fixture dump\n' >"$ROOT/source/backup/easywaf.dump"
printf 'fixture data\n' >"$ROOT/source/backup/state/data"
printf 'DATABASE_URL=postgres://fixture.invalid/never-connected\n' >/etc/easy-waf/easy-waf.env
cp /etc/easy-waf/easy-waf.env "$ROOT/source/backup/etc/easy-waf.env"
tar -czf "$ROOT/valid.tar.gz" -C "$ROOT/source" backup
export RESTORE_LOCK_TEST_ROOT="$ROOT" EASY_WAF_STATE_DIR="$ROOT/state" EASY_WAF_SKIP_APPLY=1
cat >"$ROOT/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s %s\n' "${RESTORE_LOCK_RUN:-preflight}" "$*" >>"$RESTORE_LOCK_TEST_ROOT/services"
case "$1" in
  show)
    fault="${RESTORE_STOP_FAULT:-}"
    if [[ "$fault" == initial-query ]]; then exit 42; fi
    if [[ -e "$RESTORE_LOCK_TEST_ROOT/stop-attempt" ]]; then
      if [[ "$fault" == still-active && "${@: -1}" == easy-waf-api.service ]]; then
        echo active
      else
        echo inactive
      fi
    elif [[ "${@: -1}" == easy-waf-api.service ]]; then
      echo active
    else
      echo inactive
    fi
    ;;
  stop)
    touch "$RESTORE_LOCK_TEST_ROOT/stop-attempt"
    if [[ "${RESTORE_STOP_FAULT:-}" == stop-error ]]; then exit 43; fi
    ;;
esac
if [[ "$1" == start && "${RESTORE_LOCK_HOLD:-}" == service-start ]]; then
  "$RESTORE_LOCK_TEST_ROOT/bin/barrier"
fi
MOCK
printf '#!/bin/sh\nexit 0\n' >"$ROOT/bin/chown"
cat >"$ROOT/bin/barrier" <<'MOCK'
#!/usr/bin/env bash
touch "$RESTORE_LOCK_TEST_ROOT/entered"
for ((i=0; i<500; i++)); do
  [[ ! -f "$RESTORE_LOCK_TEST_ROOT/release" ]] || exit 0
  sleep 0.02
done
exit 91
MOCK
cat >"$ROOT/bin/database" <<'MOCK'
#!/usr/bin/env bash
set -eu
operation="$(basename "$0")"
if [[ "$operation" == pg_restore && "$1" == --list ]]; then
  [[ $# == 2 && "$(cat "$2")" == 'fixture dump' ]]
  exit
fi
[[ "$1" == --dbname=service=easy-waf-archive && -n "$MOCK_PG_DSN" ]]
printf '%s %s\n' "${RESTORE_LOCK_RUN:-preflight}" "$operation" >>"$RESTORE_LOCK_TEST_ROOT/database"
if [[ "$operation" == psql ]]; then
  [[ "$*" == '--dbname=service=easy-waf-archive -XwAt -v ON_ERROR_STOP=1 -c SELECT 1' ]]
  if [[ "${RESTORE_DB_UNREACHABLE:-0}" == 1 ]]; then exit 44; fi
  printf '1\n'
  exit 0
fi
if [[ "$operation" == pg_restore && "${RESTORE_DB_FAIL:-0}" == 1 ]]; then exit 45; fi
if [[ "${RESTORE_LOCK_HOLD:-}" == "$operation" ]]; then
  "$RESTORE_LOCK_TEST_ROOT/bin/barrier"
fi
if [[ "$operation" == pg_dump ]]; then
  for argument in "$@"; do
    if [[ "$argument" == --file=* ]]; then printf 'fixture dump\n' >"${argument#--file=}"; fi
  done
fi
MOCK
cp "$(dirname "${BASH_SOURCE[0]}")/pg-archive-mock.sh" "$ROOT/bin/python3"
chmod 0700 "$ROOT/bin/"*
ln -s database "$ROOT/bin/pg_restore"
ln -s database "$ROOT/bin/pg_dump"
ln -s database "$ROOT/bin/psql"
export PATH="$ROOT/bin:$PATH"

if [[ "$mode" != locks ]]; then
  for invalid in missing empty; do
    : >"$ROOT/services"; : >"$ROOT/database"
    if [[ "$invalid" == missing ]]; then
      rm "$ROOT/source/backup/etc/easy-waf.env"
    else
      printf 'DATABASE_URL=\n' >"$ROOT/source/backup/etc/easy-waf.env"
    fi
    tar -czf "$ROOT/invalid.tar.gz" -C "$ROOT/source" backup
    if bash "$RESTORE_SCRIPT" "$ROOT/invalid.tar.gz" >"$ROOT/invalid.log" 2>&1; then
      fail "restore accepted $invalid env"
    fi
    [[ ! -s "$ROOT/services" && ! -s "$ROOT/database" ]] || fail "$invalid env touched services/database"
  done
  echo 'OK: invalid restore env rejected before service/database access'
  : >"$ROOT/services"; : >"$ROOT/database"
  cp /etc/easy-waf/easy-waf.env "$ROOT/source/backup/etc/easy-waf.env"
  printf 'unreadable fixture dump\n' >"$ROOT/source/backup/easywaf.dump"
  tar -czf "$ROOT/invalid.tar.gz" -C "$ROOT/source" backup
  if bash "$RESTORE_SCRIPT" "$ROOT/invalid.tar.gz" >"$ROOT/invalid.log" 2>&1; then
    fail 'restore accepted an unreadable dump'
  fi
  [[ ! -s "$ROOT/services" && ! -s "$ROOT/database" ]] || fail 'unreadable dump touched services/database'
  grep -Fq 'cannot read the PostgreSQL archive table of contents' "$ROOT/invalid.log" +    || fail 'unreadable dump was not diagnosed'
  echo 'OK: unreadable PostgreSQL archive rejected before service/database access'
  mkdir "$ROOT/no-flock"
  for tool in bash dirname readlink id; do ln -s "$(type -P "$tool")" "$ROOT/no-flock/$tool"; done
  ln -s "$ROOT/bin/database" "$ROOT/no-flock/pg_restore"
  : >"$ROOT/services"; : >"$ROOT/database"
  if PATH="$ROOT/no-flock" bash "$RESTORE_SCRIPT" "$ROOT/valid.tar.gz" >"$ROOT/no-flock.log" 2>&1; then
    fail 'restore continued without locking capability'
  fi
  grep -qF 'flock not found' "$ROOT/no-flock.log" || fail 'missing flock was not diagnosed'
  [[ ! -s "$ROOT/services" && ! -s "$ROOT/database" ]] || fail 'missing flock touched services/database'
  echo 'OK: missing flock rejected before service/database access'
  : >"$ROOT/services"; : >"$ROOT/database"
  if RESTORE_DB_UNREACHABLE=1 bash "$RESTORE_SCRIPT" "$ROOT/valid.tar.gz" >"$ROOT/unreachable.log" 2>&1; then
    fail 'restore accepted an unreachable database'
  fi
  [[ ! -s "$ROOT/services" ]] || fail 'unreachable database touched services'
  [[ "$(<"$ROOT/database")" == 'preflight psql' ]] || fail 'unreachable database attempted more than a connectivity check'
  grep -Fq 'cannot connect to the database configured in the backup' "$ROOT/unreachable.log" ||
    fail 'unreachable database was not diagnosed'
  echo 'OK: unreachable restore database rejected before service changes'
  for fault in initial-query stop-error still-active; do
    : >"$ROOT/services"; : >"$ROOT/database"
    rm -f "$ROOT/stop-attempt"
    printf 'original state\n' >"$ROOT/state/original"
    cp /etc/easy-waf/easy-waf.env "$ROOT/original-env"
    rc=0
    RESTORE_STOP_FAULT="$fault" bash "$RESTORE_SCRIPT" "$ROOT/valid.tar.gz" >"$ROOT/quiesce.log" 2>&1 || rc=$?
    [[ "$rc" == 1 ]] || fail "$fault did not abort restore"
    grep -Fq 'restore aborted before database changes' "$ROOT/quiesce.log" || fail "$fault did not explain the abort"
    [[ "$(<"$ROOT/database")" == 'preflight psql' &&
       ! -e "$ROOT/state/data" && -f "$ROOT/state/original" ]] || fail "$fault changed database or state"
    cmp -s "$ROOT/original-env" /etc/easy-waf/easy-waf.env || fail "$fault changed configuration"
    if [[ "$fault" == initial-query ]]; then
      if grep -Eq '^preflight (stop|start) ' "$ROOT/services"; then fail 'initial query failure changed services'; fi
    else
      diff -u <(printf 'preflight start easy-waf-api.service\n') <(grep '^preflight start ' "$ROOT/services") \
        || fail "$fault did not resume only the originally active service"
    fi
  done
  echo 'OK: restore requires confirmed writer quiescence before replacing data'
  : >"$ROOT/services"; : >"$ROOT/database"
  rm -f "$ROOT/stop-attempt"
  if RESTORE_DB_FAIL=1 bash "$RESTORE_SCRIPT" "$ROOT/valid.tar.gz" >"$ROOT/failed-db.log" 2>&1; then
    fail 'restore ignored pg_restore failure'
  fi
  [[ "$(<"$ROOT/database")" == $'preflight psql\npreflight pg_restore' &&
     -f "$ROOT/state/original" && ! -e "$ROOT/state/data" ]] || fail 'pg_restore failure changed live state'
  if grep -q '^preflight start ' "$ROOT/services"; then fail 'pg_restore failure restarted services'; fi
  grep -Fq 'Verify the database outcome before restarting appliance services' "$ROOT/failed-db.log" ||
    fail 'pg_restore failure did not explain recovery'
  echo 'OK: failed pg_restore keeps existing files and leaves services stopped'
fi

if [[ "$mode" != preflight ]]; then
  for holder in backup restore; do
    for phase in database startup; do
      rm -f "$ROOT/entered" "$ROOT/release" "$ROOT/stop-attempt"
      : >"$ROOT/services"; : >"$ROOT/database"
      script="$BACKUP_SCRIPT"; argument="$ROOT/held-backup.tar.gz"; hold=pg_dump
      if [[ "$holder" == restore ]]; then script="$RESTORE_SCRIPT"; argument="$ROOT/valid.tar.gz"; hold=pg_restore; fi
      if [[ "$phase" == startup ]]; then hold=service-start; fi
      RESTORE_LOCK_RUN=holder RESTORE_LOCK_HOLD="$hold" bash "$script" "$argument" >"$ROOT/holder.log" 2>&1 &
      HOLDER_PID=$!
      for ((i=0; i<500; i++)); do
        [[ ! -f "$ROOT/entered" ]] || break
        sleep 0.02
      done
      [[ -f "$ROOT/entered" ]] || fail 'holder did not reach database barrier'
      for competitor in backup restore; do
        script="$BACKUP_SCRIPT"; argument="$ROOT/rejected-backup.tar.gz"
        if [[ "$competitor" == restore ]]; then script="$RESTORE_SCRIPT"; argument="$ROOT/valid.tar.gz"; fi
        if RESTORE_LOCK_RUN=competitor RESTORE_LOCK_HOLD='' bash "$script" "$argument" >"$ROOT/rejected.log" 2>&1; then
          fail "$competitor overlapped $holder"
        fi
        grep -qi 'lock' "$ROOT/rejected.log" || fail 'overlap failed for an unrelated reason'
        if grep -q '^competitor ' "$ROOT/services" "$ROOT/database"; then fail 'rejected operation reached services/database'; fi
      done
      touch "$ROOT/release"
      wait "$HOLDER_PID" || { cat "$ROOT/holder.log"; fail 'holder failed'; }
      HOLDER_PID=''
    done
  done
  echo 'OK: backup/restore locks cover database work and writer startup against both competitors'
fi
