#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
# Exercise actual upgrade preparation without installing payloads or restarting services.
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/repo/scripts/lib" "$ROOT/input" "$ROOT/private temp"
# Keep the real script through its installer call; its service-restart tail is
# outside this filesystem fixture. Refuse an unexpected script layout.
grep -q '^# This outer installer has finished' "$SOURCE_DIR/upgrade.sh"
sed '/^# This outer installer has finished/,$d' "$SOURCE_DIR/upgrade.sh" >"$ROOT/repo/scripts/upgrade.sh"
cp "$SOURCE_DIR/lib/release-unpack.sh" "$ROOT/repo/scripts/lib/"
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
  export TMPDIR="$ROOT/private temp/$name"
  mkdir -p "$TMPDIR"
  export TEST_INSTALL_MARKER="$ROOT/$name.called" TEST_STAGE_PATH="$ROOT/$name.stage" TEST_INSTALL_EXIT="$install_exit"
  unset EASY_WAF_INSTALL_POSTGRES
  bash "$ROOT/repo/scripts/upgrade.sh" "$input" >"$ROOT/$name.log" 2>&1 || status=$?
  if [[ "$accepted" == yes ]]; then
    [[ -f "$TEST_INSTALL_MARKER" && "$status" == "$install_exit" ]] || fail "$name did not reach the fixture installer correctly"
    if [[ -f "$TEST_STAGE_PATH" ]]; then
      stage="$(cat "$TEST_STAGE_PATH")"
      [[ "$stage" == "$TMPDIR/"* && ! -e "$stage" ]] || fail "$name did not clean its private stage"
    fi
  else
    [[ "$status" != 0 && ! -e "$TEST_INSTALL_MARKER" ]] || fail "$name reached installer with invalid input"
  fi
  [[ -z "$(find "$TMPDIR" -mindepth 1 -print -quit)" ]] || fail "$name leaked temporary files"
}

populate "$ROOT/input/flat"
tar -czf "$ROOT/flat.tar.gz" -C "$ROOT/input/flat" .
run_case flat "$ROOT/flat.tar.gz" yes
run_case installer_failure "$ROOT/flat.tar.gz" yes 7
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
echo 'OK: upgrade stages complete inputs, preserves sources and cleans all exits'
