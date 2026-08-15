#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/management-listen.sh
source "${SCRIPT_DIR}/lib/management-listen.sh"

[[ "$(easy_waf_default_management_mode)" == "https_loopback" ]] || {
  echo "management default must be HTTPS-only loopback" >&2
  exit 1
}

assert_mode() {
  local mode="$1"
  local expected="$2"
  local actual
  actual="$(easy_waf_management_mode_listeners "$mode")"
  [[ "$actual" == "$expected" ]] || {
    echo "mode $mode: got $actual, want $expected" >&2
    return 1
  }
}

assert_mode "https_loopback" "off|127.0.0.1:8443"
assert_mode "loopback" "127.0.0.1:8000|127.0.0.1:8443"
assert_mode "lan_rfc1918" "off|0.0.0.0:8443"

if easy_waf_management_mode_listeners "unknown" >/dev/null 2>&1; then
  echo "unknown management mode must fail" >&2
  exit 1
fi

echo "management listen modes: OK"
