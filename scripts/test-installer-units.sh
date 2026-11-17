#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir -p "$ROOT/scripts/lib"
[[ "$(tail -n 1 "$SOURCE_DIR/install.sh")" == 'main "$@"' ]]
sed '$d' "$SOURCE_DIR/install.sh" >"$ROOT/scripts/install.sh"
cp "$SOURCE_DIR/lib/env-file.sh" "$ROOT/scripts/lib/"
# shellcheck source=/dev/null
source "$ROOT/scripts/install.sh"

core='enable --now easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service'
check_timer='is-enabled --quiet easy-waf-backup.timer'
start_timer='start easy-waf-backup.timer'
systemctl() {
  printf '%s\n' "$*" >>"$ROOT/systemctl"
  case "$*" in
    "$core") return "$core_status" ;;
    "$check_timer") return "$timer_disabled" ;;
    "$start_timer") return "$timer_start_status" ;;
    *) return 99 ;;
  esac
}

run_case() {
  local name="$1" expected_status="$2" expected_calls="$3" status=0
  : >"$ROOT/systemctl"
  start_appliance_units >"$ROOT/result.log" || status=$?
  if [[ "$status" != "$expected_status" || "$(cat "$ROOT/systemctl")" != "$expected_calls" ]]; then
    printf 'FAIL: %s. Exit status %s, systemctl calls:\n' "$name" "$status" >&2
    cat "$ROOT/systemctl" >&2
    exit 1
  fi
}

unset EASY_WAF_ENABLE_SYSTEMD_UNITS EASY_WAF_SKIP_SYSTEMD
export EASY_WAF_PKG_INSTALLED=1
core_status=0
timer_disabled=0
timer_start_status=0
run_case 'enabled packaged timer' 0 "$core"$'\n'"$check_timer"$'\n'"$start_timer"
timer_disabled=1
run_case 'operator opted out' 0 "$core"$'\n'"$check_timer"
timer_disabled=0
timer_start_status=5
run_case 'timer start failure' 1 "$core"$'\n'"$check_timer"$'\n'"$start_timer"
grep -q 'ERROR: could not start enabled backup timer' "$ROOT/result.log"
timer_start_status=0
core_status=1
run_case 'core startup failed' 0 "$core"
core_status=0
EASY_WAF_PKG_INSTALLED=0
run_case 'unpackaged install starts its timer in unit installation' 0 "$core"
EASY_WAF_PKG_INSTALLED=1
export EASY_WAF_ENABLE_SYSTEMD_UNITS=0
run_case 'startup disabled' 0 ''
EASY_WAF_ENABLE_SYSTEMD_UNITS=1
export EASY_WAF_SKIP_SYSTEMD=1
run_case 'systemd skipped' 0 ''
echo 'OK: package installer starts enabled backup timer after provisioning'
