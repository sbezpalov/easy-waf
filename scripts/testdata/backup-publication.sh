#!/usr/bin/env bash
# Inner fixture: never run on an appliance. The launcher supplies a private mount.
set -euo pipefail
BACKUP_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backup.sh"
[[ "$(id -u)" == 0 ]] || { echo 'Fixture requires container root' >&2; exit 1; }
awk '$2 == "/etc/easy-waf" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts || {
  echo 'Refusing backup fixture without private config tmpfs' >&2; exit 1;
}
ROOT="$(mktemp -d)"
FIRST_PID=""
SECOND_PID=""
cleanup() {
  touch "$ROOT/release-first" "$ROOT/release-second"
  if [[ -n "$FIRST_PID" ]]; then wait "$FIRST_PID" || true; fi
  if [[ -n "$SECOND_PID" ]]; then wait "$SECOND_PID" || true; fi
  rm -rf "$ROOT"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$ROOT/bin" "$ROOT/state" "$ROOT/output"
printf 'fixture-state\n' >"$ROOT/state/data"
printf 'DATABASE_URL=postgres://fixture.invalid/never-connected\n' >/etc/easy-waf/easy-waf.env
export BACKUP_TEST_ROOT="$ROOT" BACKUP_TEST_MODE=ok
BACKUP_TEST_REAL_TAR="$(type -P tar)"
export BACKUP_TEST_REAL_TAR
export EASY_WAF_STATE_DIR="$ROOT/state" EASY_WAF_ENV_FILE=/etc/easy-waf/easy-waf.env
cat >"$ROOT/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
if [[ -n "${BACKUP_TEST_RUN:-}" ]]; then
  printf '%s %s\n' "$BACKUP_TEST_RUN" "$*" >>"$BACKUP_TEST_ROOT/concurrent-services"
else
  printf '%s\n' "$*" >>"$BACKUP_TEST_ROOT/services"
fi
case "$1" in
  show)
    if [[ "$BACKUP_TEST_MODE" == query-fail && "${@: -1}" == easy-waf-acmed.service ]]; then exit 25; fi
    if [[ -f "$BACKUP_TEST_ROOT/inactive-${@: -1}" ]]; then echo inactive; else echo active; fi
    ;;
  stop)
    if [[ "$BACKUP_TEST_MODE" != still-active || "$2" != easy-waf-acmed.service ]]; then
      touch "$BACKUP_TEST_ROOT/inactive-$2"
    fi
    ;;
  start)
    if [[ -f "$BACKUP_TEST_ROOT/entered-second" && ! -f "$BACKUP_TEST_ROOT/release-second" ]]; then
      touch "$BACKUP_TEST_ROOT/resumed-during-dump"
    fi
    rm -f "$BACKUP_TEST_ROOT/inactive-$2"
    if [[ "$BACKUP_TEST_MODE" == restart-fail && "$2" == easy-waf-api.service ]]; then exit 26; fi
    ;;
esac
MOCK
cat >"$ROOT/bin/pg_dump" <<'MOCK'
#!/usr/bin/env bash
touch "$BACKUP_TEST_ROOT/dump-called"
[[ "$1" == postgres://fixture.invalid/never-connected ]] || exit 90
[[ "$BACKUP_TEST_MODE" != dump-fail ]] || exit 21
if [[ -n "${BACKUP_TEST_RUN:-}" ]]; then
  touch "$BACKUP_TEST_ROOT/entered-$BACKUP_TEST_RUN"
  ready=0
  for ((i=0; i<1500; i++)); do
    if [[ -f "$BACKUP_TEST_ROOT/release-$BACKUP_TEST_RUN" ]]; then ready=1; break; fi
    sleep 0.02
  done
  ((ready)) || exit 92
fi
for arg in "$@"; do
  if [[ "$arg" == --file=* ]]; then printf 'fixture-dump\n' >"${arg#--file=}"; exit 0; fi
done
exit 91
MOCK
cat >"$ROOT/bin/tar" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == -czf ]]; then
  if [[ "$BACKUP_TEST_MODE" == pack-fail ]]; then printf 'partial-output' >"$2"; exit 22; fi
  if [[ "$BACKUP_TEST_MODE" == inspect ]]; then
    [[ -f "$2" && "$(stat -c %a "$2")" == 600 ]] || exit 23
    [[ "$(stat -c %a "$(dirname "$2")")" == 700 ]] || exit 24
  fi
fi
exec "$BACKUP_TEST_REAL_TAR" "$@"
MOCK
chmod 0700 "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"
backup() {
  local expected_status="$1" status=0 unit
  shift
  : >"$ROOT/services"
  bash "$BACKUP_SCRIPT" "$@" >"$ROOT/log" 2>&1 || status=$?
  if [[ "$expected_status" == pass ]]; then
    [[ "$status" == 0 ]] || { cat "$ROOT/log" >&2; fail 'backup did not complete'; }
  else
    [[ "$status" != 0 ]] || fail 'backup accepted a failed operation'
  fi
  for unit in easy-waf-api.service easy-waf-acmed.service; do
    grep -qxF "stop $unit" "$ROOT/services" || fail 'writer not stopped'
    grep -qxF "start $unit" "$ROOT/services" || fail 'writer not restarted'
  done
}
out="$ROOT/output/backup.tar.gz"
printf 'protected-target\n' >"$ROOT/protected"
cp "$ROOT/protected" "$ROOT/expected"
ln -s "$ROOT/protected" "$out.partial"
backup pass "$out"
cmp -s "$ROOT/protected" "$ROOT/expected" || fail 'partial symlink target overwritten'
[[ -L "$out.partial" ]] || fail 'unowned partial symlink removed'
rm "$out.partial"
ln "$ROOT/protected" "$out.partial"
backup pass "$out"
cmp -s "$ROOT/protected" "$ROOT/expected" || fail 'partial hardlink target overwritten'
[[ -f "$out.partial" ]] || fail 'unowned partial hardlink removed'
rm "$out.partial"
rm "$out"
ln -s "$ROOT/protected" "$out"
backup pass "$out"
[[ ! -L "$out" ]] || fail 'final output symlink not replaced'
cmp -s "$ROOT/protected" "$ROOT/expected" || fail 'final output symlink target changed'
rm "$out"
ln "$ROOT/protected" "$out"
backup pass "$out"
cmp -s "$ROOT/protected" "$ROOT/expected" || fail 'final output hardlink target changed'
printf 'unowned-partial\n' >"$out.partial"
printf 'previous-backup\n' >"$out"
for mode in dump-fail pack-fail; do
  export BACKUP_TEST_MODE="$mode"
  backup fail "$out"
  [[ "$(cat "$out")" == previous-backup ]] || fail 'failure damaged previous backup'
  [[ -f "$out.partial" && "$(cat "$out.partial")" == unowned-partial ]] || fail 'failure removed unowned partial'
done
for mode in query-fail still-active; do
  rm -f "$ROOT/dump-called"
  : >"$ROOT/services"
  rc=0
  BACKUP_TEST_MODE="$mode" bash "$BACKUP_SCRIPT" "$out" >"$ROOT/log" 2>&1 || rc=$?
  [[ "$rc" == 1 ]] || fail "$mode did not abort backup"
  grep -Fq 'backup aborted before pg_dump' "$ROOT/log" || fail "$mode not diagnosed"
  [[ ! -e "$ROOT/dump-called" && "$(<"$out")" == previous-backup ]] || fail "$mode touched dump or prior archive"
  if [[ "$mode" == query-fail ]]; then
    if grep -Eq '^(start|stop) ' "$ROOT/services"; then fail 'initial query failure changed services'; fi
  else
    grep -qxF 'start easy-waf-api.service' "$ROOT/services" || fail 'quiescence failure left API stopped'
    grep -qxF 'start easy-waf-acmed.service' "$ROOT/services" || fail 'quiescence failure did not attempt ACME recovery'
  fi
done
echo 'OK: backup requires confirmed writer quiescence before pg_dump'
BACKUP_TEST_MODE=restart-fail backup fail "$out"
grep -Fq 'but writer recovery is incomplete' "$ROOT/log" || fail 'restart failure did not state archive was retained'
if grep -q '^\[easy-waf-backup\] done:' "$ROOT/log"; then fail 'restart failure printed success'; fi
"$BACKUP_TEST_REAL_TAR" -tzf "$out" >/dev/null || fail 'restart failure lost the complete archive'
echo 'OK: backup keeps the complete archive and reports restart failure'
export BACKUP_TEST_MODE=ok
mkdir "$ROOT/output/directory"
backup fail "$ROOT/output/directory"
[[ -z "$(find "$ROOT/output/directory" -mindepth 1 -print)" ]] || fail 'backup moved inside output directory'
export BACKUP_TEST_MODE=inspect
(umask 000; backup pass "$out")
[[ "$(stat -c %a "$out")" == 600 ]] || fail 'backup permissions not private'
"$BACKUP_TEST_REAL_TAR" -tzf "$out" >"$ROOT/members"
top="$(head -n 1 "$ROOT/members")"
[[ "$top" == easy-waf-backup-*/ ]] || fail 'backup format root changed'
[[ "$("$BACKUP_TEST_REAL_TAR" -xOzf "$out" "${top}easywaf.dump")" == fixture-dump ]] || fail 'dump missing'
[[ "$("$BACKUP_TEST_REAL_TAR" -xOzf "$out" "${top}state/data")" == fixture-state ]] || fail 'state missing'
"$BACKUP_TEST_REAL_TAR" -xOzf "$out" "${top}etc/easy-waf.env" | cmp - /etc/easy-waf/easy-waf.env
mkdir "$ROOT/rotated"
: >"$ROOT/rotated/easy-waf-backup-20200101-000000.tar.gz"
backup pass --dir "$ROOT/rotated" --keep 1
[[ ! -e "$ROOT/rotated/easy-waf-backup-20200101-000000.tar.gz" ]] || fail 'old backup not rotated'
[[ "$(find "$ROOT/rotated" -name '*.tar.gz' | wc -l)" == 1 ]] || fail 'rotation count changed'
[[ -z "$(find "$ROOT/output" "$ROOT/rotated" -name '.easy-waf-backup.*' -print)" ]] || fail 'owned staging left behind'

# No locking capability must fail before service/dump access, not run unlocked.
mkdir "$ROOT/no-flock-bin"
for tool in bash date dirname readlink id; do
  ln -s "$(type -P "$tool")" "$ROOT/no-flock-bin/$tool"
done
: >"$ROOT/services"
rm "$ROOT/dump-called"
if PATH="$ROOT/no-flock-bin" bash "$BACKUP_SCRIPT" "$ROOT/output/no-lock.tar.gz" >"$ROOT/no-lock-log" 2>&1; then
  fail 'backup continued without flock'
fi
grep -qF 'flock not found' "$ROOT/no-lock-log" || fail 'missing flock was not diagnosed'
[[ ! -s "$ROOT/services" && ! -e "$ROOT/dump-called" ]] || fail 'missing lock capability touched writers or dump'

# Separate invocations share writer services even when their output paths differ.
export BACKUP_TEST_MODE=ok
wait_for() {
  local path="$1" i
  for ((i=0; i<500; i++)); do
    [[ ! -e "$path" ]] || return 0
    sleep 0.02
  done
  fail 'backup barrier timed out'
}
(
  status=0
  BACKUP_TEST_RUN=first bash "$BACKUP_SCRIPT" "$ROOT/output/first.tar.gz" >"$ROOT/first-log" 2>&1 || status=$?
  printf '%s\n' "$status" >"$ROOT/status-first"
) &
FIRST_PID=$!
wait_for "$ROOT/entered-first"
for unit in easy-waf-api.service easy-waf-acmed.service; do
  [[ -f "$ROOT/inactive-$unit" ]] || fail 'first backup did not quiesce writer'
done
(
  status=0
  BACKUP_TEST_RUN=second bash "$BACKUP_SCRIPT" "$ROOT/output/second.tar.gz" >"$ROOT/second-log" 2>&1 || status=$?
  printf '%s\n' "$status" >"$ROOT/status-second"
) &
SECOND_PID=$!
for ((i=0; i<500; i++)); do
  if [[ -e "$ROOT/entered-second" || -e "$ROOT/status-second" ]]; then break; fi
  sleep 0.02
done
[[ -e "$ROOT/entered-second" || -e "$ROOT/status-second" ]] || fail 'second invocation timed out'
touch "$ROOT/release-first"
wait "$FIRST_PID"
FIRST_PID=""
[[ ! -e "$ROOT/resumed-during-dump" ]] || fail 'writers resumed while another backup was dumping'
[[ ! -e "$ROOT/entered-second" ]] || fail 'overlapping backup reached dump'
wait "$SECOND_PID"
SECOND_PID=""
[[ "$(cat "$ROOT/status-first")" == 0 && "$(cat "$ROOT/status-second")" != 0 ]] || fail 'backup overlap status incorrect'
if grep -q '^second ' "$ROOT/concurrent-services"; then fail 'rejected backup touched services'; fi
[[ ! -e "$ROOT/output/second.tar.gz" ]] || fail 'rejected backup published output'
"$BACKUP_TEST_REAL_TAR" -tzf "$ROOT/output/first.tar.gz" >/dev/null
backup pass "$ROOT/output/retry.tar.gz"
echo 'OK: overlapping backup rejected before writer or dump access; retry succeeds'
echo 'OK: real backup preserves targets, previous archives and writer restarts'
