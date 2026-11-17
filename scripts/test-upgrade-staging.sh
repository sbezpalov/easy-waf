#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
# Exercise upgrade preparation and restart results with isolated commands.
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/repo/scripts/lib" "$ROOT/input" "$ROOT/private temp" "$ROOT/bin"
# Redirect the absolute helper path to the fixture. Expand the variable when
# the copied script runs, so paths with spaces stay quoted.
grep -Eq '^(if ! )?/usr/sbin/easy-waf-hostd restart-after-packages' "$SOURCE_DIR/upgrade.sh"
# shellcheck disable=SC2016
sed 's|/usr/sbin/easy-waf-hostd|"$TEST_RESTART_HELPER"|' "$SOURCE_DIR/upgrade.sh" >"$ROOT/repo/scripts/upgrade.sh"
cp "$SOURCE_DIR/lib/release-unpack.sh" "$ROOT/repo/scripts/lib/"
cat >"$ROOT/bin/easy-waf-hostd" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 1 && "$1" == restart-after-packages ]]
printf 'broker\n' >>"$TEST_RESTART_LOG"
exit "$TEST_BROKER_EXIT"
STUB
cat >"$ROOT/bin/systemctl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" == 3 && "$1" == try-restart && "$2" == --no-block ]]
printf '%s\n' "$3" >>"$TEST_RESTART_LOG"
case "$3" in
  easy-waf-api.service) exit "$TEST_API_EXIT" ;;
  easy-waf-acmed.service) exit "$TEST_ACME_EXIT" ;;
  *) exit 2 ;;
esac
STUB
chmod +x "$ROOT/bin/"{easy-waf-hostd,systemctl}
export PATH="$ROOT/bin:$PATH" TEST_RESTART_HELPER="$ROOT/bin/easy-waf-hostd"
cat >"$ROOT/repo/scripts/install.sh" <<'STUB'
set -euo pipefail
printf 'called\n' >"$TEST_INSTALL_MARKER"
printf '%s\n' "$EASY_WAF_DIST_DIR" >"$TEST_STAGE_PATH"
for binary in easy-waf-api easy-waf-acmed easy-waf-hostd easy-waf-admin; do
  [[ "$(cat "$EASY_WAF_DIST_DIR/$binary")" == "fixture-$binary" ]]
done
[[ "${EASY_WAF_INSTALL_POSTGRES:-}" == 0 ]]
exit "$TEST_INSTALL_EXIT"
STUB
errors=0
fail() { echo "FAIL: $*" >&2; errors=$((errors + 1)); }
populate() {
  mkdir -p "$1"
  local binary
  for binary in easy-waf-api easy-waf-acmed easy-waf-hostd easy-waf-admin; do
    printf 'fixture-%s\n' "$binary" >"$1/$binary"
    chmod 0755 "$1/$binary"
  done
}
run_case() {
  local name="$1" input="$2" accepted="$3" install_exit="${4:-0}" status=0 stage
  local expected_status="${5:-$install_exit}"
  export TMPDIR="$ROOT/private temp/$name"
  mkdir -p "$TMPDIR"
  export TEST_INSTALL_MARKER="$ROOT/$name.called" TEST_STAGE_PATH="$ROOT/$name.stage" TEST_INSTALL_EXIT="$install_exit"
  export TEST_RESTART_LOG="$ROOT/$name.restarts"
  export TEST_BROKER_EXIT="${6:-0}" TEST_API_EXIT="${7:-0}" TEST_ACME_EXIT="${8:-0}"
  unset EASY_WAF_INSTALL_POSTGRES
  bash "$ROOT/repo/scripts/upgrade.sh" "$input" >"$ROOT/$name.log" 2>&1 || status=$?
  if [[ "$accepted" == yes ]]; then
    [[ -f "$TEST_INSTALL_MARKER" ]] || fail "$name did not reach the fixture installer"
    [[ "$status" == "$expected_status" ]] || fail "$name returned $status, expected $expected_status"
    if [[ -f "$TEST_STAGE_PATH" ]]; then
      stage="$(cat "$TEST_STAGE_PATH")"
      [[ "$stage" == "$TMPDIR/"* && ! -e "$stage" ]] || fail "$name did not clean its private stage"
    fi
  else
    [[ "$status" != 0 && ! -e "$TEST_INSTALL_MARKER" ]] || fail "$name reached installer with invalid input"
  fi
  if [[ "$accepted" == yes && "$install_exit" == 0 ]]; then
    [[ -f "$TEST_RESTART_LOG" && "$(cat "$TEST_RESTART_LOG")" == $'broker\neasy-waf-api.service\neasy-waf-acmed.service' ]] ||
      fail "$name did not attempt all restart requests in order"
    if [[ "$expected_status" != 0 ]] && grep -q '^Requested package-safe' "$ROOT/$name.log"; then
      fail "$name printed restart success after a failure"
    fi
  else
    [[ ! -e "$TEST_RESTART_LOG" ]] || fail "$name attempted a restart after an unsuccessful install"
  fi
  [[ -z "$(find "$TMPDIR" -mindepth 1 -print -quit)" ]] || fail "$name leaked temporary files"
}

populate "$ROOT/input/flat"
tar -czf "$ROOT/flat.tar.gz" -C "$ROOT/input/flat" .
run_case flat "$ROOT/flat.tar.gz" yes
run_case installer_failure "$ROOT/flat.tar.gz" yes 7
run_case broker_failure "$ROOT/flat.tar.gz" yes 0 1 3
grep -Fq 'ERROR: package-safe APT/broker restart failed' "$ROOT/broker_failure.log" || fail 'missing broker failure message'
run_case api_queue_failure "$ROOT/flat.tar.gz" yes 0 1 0 4
grep -Fq 'ERROR: could not queue restart for easy-waf-api.service' "$ROOT/api_queue_failure.log" || fail 'missing API failure message'
run_case acme_queue_failure "$ROOT/flat.tar.gz" yes 0 1 0 0 5
grep -Fq 'ERROR: could not queue restart for easy-waf-acmed.service' "$ROOT/acme_queue_failure.log" || fail 'missing ACME failure message'
populate "$ROOT/input/nested/dist"
tar -czf "$ROOT/nested.tar.gz" -C "$ROOT/input/nested" .
run_case nested "$ROOT/nested.tar.gz" yes
populate "$ROOT/input/wrapped/wrapped release/dist"
tar -czf "$ROOT/wrapped.tar.gz" -C "$ROOT/input/wrapped" .
run_case wrapped "$ROOT/wrapped.tar.gz" yes

populate "$ROOT/input/directory with spaces/dist"
run_case directory "$ROOT/input/directory with spaces" yes
for binary in easy-waf-api easy-waf-acmed easy-waf-hostd easy-waf-admin; do
  [[ -f "$ROOT/input/directory with spaces/dist/$binary" ]] || fail "directory source was moved: $binary"
done
populate "$ROOT/input/missing"
rm "$ROOT/input/missing/easy-waf-admin"
tar -czf "$ROOT/missing.tar.gz" -C "$ROOT/input/missing" .
run_case missing "$ROOT/missing.tar.gz" no
run_case missing_directory "$ROOT/input/missing" no
populate "$ROOT/input/empty"
: >"$ROOT/input/empty/easy-waf-admin"
tar -czf "$ROOT/empty.tar.gz" -C "$ROOT/input/empty" .
run_case empty "$ROOT/empty.tar.gz" no
cp "$ROOT/input/nested/dist/easy-waf-api" "$ROOT/input/nested/easy-waf-api"
tar -czf "$ROOT/duplicate.tar.gz" -C "$ROOT/input/nested" .
run_case duplicate "$ROOT/duplicate.tar.gz" no
bytes="$(wc -c <"$ROOT/flat.tar.gz")"
dd if="$ROOT/flat.tar.gz" of="$ROOT/truncated.tar.gz" bs=1 count="$((bytes - 8))" 2>/dev/null
run_case truncated "$ROOT/truncated.tar.gz" no
[[ "$errors" == 0 ]] || exit 1
echo 'OK: upgrade staging, cleanup and restart results'
