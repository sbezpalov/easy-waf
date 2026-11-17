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

enable_core='enable easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service'
start_hostd='start easy-waf-hostd.service'
start_api='start easy-waf-api.service'
start_acmed='start easy-waf-acmed.service'
core="$enable_core"$'\n'"$start_hostd"$'\n'"$start_api"$'\n'"$start_acmed"
check_timer='is-enabled --quiet easy-waf-backup.timer'
start_timer='start easy-waf-backup.timer'
systemctl() {
  printf '%s\n' "$*" >>"$ROOT/systemctl"
  case "$*" in
    "$enable_core") return "$enable_status" ;;
    "$start_hostd") return 0 ;;
    "$start_api") return "$api_status" ;;
    "$start_acmed") return "$acmed_status" ;;
    "$check_timer") return "$timer_disabled" ;;
    "$start_timer") return "$timer_start_status" ;;
    *) return 99 ;;
  esac
}

run_case() {
  local name="$1" expected_status="$2" expected_calls="$3" status=0
  : >"$ROOT/systemctl"
  start_appliance_units >"$ROOT/result.log" 2>&1 || status=$?
  if [[ "$status" != "$expected_status" || "$(cat "$ROOT/systemctl")" != "$expected_calls" ]]; then
    printf 'FAIL: %s. Exit status %s, systemctl calls:\n' "$name" "$status" >&2
    cat "$ROOT/systemctl" >&2
    exit 1
  fi
}

unset EASY_WAF_ENABLE_SYSTEMD_UNITS EASY_WAF_SKIP_SYSTEMD
export EASY_WAF_PKG_INSTALLED=1
enable_status=0
api_status=0
acmed_status=0
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
enable_status=3
run_case 'core enable failed' 3 "$enable_core"
grep -q 'ERROR: could not enable appliance services' "$ROOT/result.log"
enable_status=0
api_status=4
acmed_status=5
run_case 'individual starts failed' 4 "$core"
grep -q 'ERROR: could not start easy-waf-api.service (systemctl exit 4)' "$ROOT/result.log"
grep -q 'ERROR: could not start easy-waf-acmed.service (systemctl exit 5)' "$ROOT/result.log"
api_status=0
acmed_status=0
EASY_WAF_PKG_INSTALLED=0
run_case 'unpackaged install starts its timer in unit installation' 0 "$core"
EASY_WAF_PKG_INSTALLED=1
export EASY_WAF_ENABLE_SYSTEMD_UNITS=0
run_case 'startup disabled' 0 ''
EASY_WAF_ENABLE_SYSTEMD_UNITS=1
export EASY_WAF_SKIP_SYSTEMD=1
run_case 'systemd skipped' 0 ''
echo 'OK: installer reports service failures and starts the enabled backup timer after provisioning'
