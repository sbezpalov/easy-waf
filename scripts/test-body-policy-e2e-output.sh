#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
# Exercise the real E2E result handling without Docker, networking or sleeps.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir "$WORK/bin"
cat >"$WORK/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1" == ps ]]; then
  echo body-e2e-haproxy
elif [[ "$1" == run && " $* " == *' --entrypoint sh '* ]]; then
  case "$BODY_POLICY_OUTPUT_CASE" in
    transport_failure) exit 42 ;;
    empty_success) exit 0 ;;
    partial_failure) echo '200 200 fixture'; exit 42 ;;
    partial_success) echo '200 200 fixture'; exit 0 ;;
    success | http_failure)
      first=1
      while IFS= read -r line; do
        if [[ "$line" =~ ^check[[:space:]]+([0-9]+)[[:space:]] ]]; then
          want="${BASH_REMATCH[1]}"
          got="$want"
          if [[ "$BODY_POLICY_OUTPUT_CASE" == http_failure && "$first" == 1 ]]; then got=503; fi
          first=0
          printf '%s %s fixture\n' "$want" "$got"
        fi
      done
      ;;
    *) exit 90 ;;
  esac
fi
MOCK
printf '#!/bin/sh\nexit 0\n' >"$WORK/bin/sleep"
chmod 0700 "$WORK/bin/"*
export PATH="$WORK/bin:$PATH"
[[ "$(command -v docker)" == "$WORK/bin/docker" ]] || fail 'Docker mock not selected'
for scenario in transport_failure partial_failure empty_success partial_success http_failure success; do
  result=0
  BODY_POLICY_OUTPUT_CASE="$scenario" bash "$SCRIPT_DIR/test-body-policy-e2e.sh" >"$WORK/$scenario.log" 2>&1 || result=$?
  if [[ "$scenario" == success ]]; then
    [[ "$result" == 0 ]] || { cat "$WORK/$scenario.log" >&2; fail 'complete passing suite rejected'; }
    grep -q '^OK: multipart block and body limit hold$' "$WORK/$scenario.log" || fail 'missing success summary'
  else
    [[ "$result" != 0 ]] || fail "$scenario falsely accepted"
    if grep -q '^OK:' "$WORK/$scenario.log"; then fail "$scenario printed false success"; fi
  fi
  echo "PASS: body E2E output $scenario"
done
