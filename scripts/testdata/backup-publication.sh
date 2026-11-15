#!/usr/bin/env bash
# Inner fixture: never run on an appliance. The launcher supplies a private mount.
set -euo pipefail
BACKUP_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/backup.sh"
[[ "$(id -u)" == 0 ]] || { echo 'Fixture requires container root' >&2; exit 1; }
awk '$2 == "/etc/easy-waf" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts || {
  echo 'Refusing backup fixture without private config tmpfs' >&2; exit 1;
}
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
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
printf '%s\n' "$*" >>"$BACKUP_TEST_ROOT/services"
MOCK
cat >"$ROOT/bin/pg_dump" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == postgres://fixture.invalid/never-connected ]] || exit 90
[[ "$BACKUP_TEST_MODE" != dump-fail ]] || exit 21
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
echo 'OK: real backup preserves targets, previous archives and writer restarts'
