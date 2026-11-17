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
export DOCKER_CALLS="$WORK/docker-calls"
cat >"$WORK/bin/docker" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$DOCKER_CALLS"
if [[ "$1 ${2:-}" == 'network create' ]]; then
  [[ "$BODY_POLICY_OUTPUT_CASE" != subnet_conflict ]] || exit 43
  echo owned-network
elif [[ "$1" == create ]]; then
  [[ "$2 $3" == '--network owned-network' ]] || exit 91
  if [[ " $* " == *' --ip 10.78.0.30 '* ]]; then echo owned-app; else echo owned-haproxy; fi
elif [[ "$1 ${2:-}" == 'start owned-haproxy' ]]; then
  [[ "$BODY_POLICY_OUTPUT_CASE" != start_failure ]] || exit 44
elif [[ "$1" == inspect ]]; then
  [[ "${*: -1}" == owned-haproxy ]] || exit 92
  echo true
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

for scenario in subnet_conflict start_failure; do
  : >"$DOCKER_CALLS"
  result=0
  BODY_POLICY_OUTPUT_CASE="$scenario" bash "$SCRIPT_DIR/test-body-policy-e2e.sh" >"$WORK/$scenario.log" 2>&1 || result=$?
  if [[ "$scenario" == subnet_conflict ]]; then
    [[ "$result" == 43 && "$(wc -l <"$DOCKER_CALLS")" -eq 1 ]] || fail 'failed network creation touched another resource'
    grep -q '^network create ' "$DOCKER_CALLS" || fail 'expected network creation attempt'
  else
    [[ "$result" == 44 ]] || fail 'failed HAProxy start did not reach cleanup'
    diff -u <(printf '%s\n' 'rm -f owned-haproxy' 'rm -f owned-app' 'network rm owned-network') \
      <(grep -E '^(rm |network rm )' "$DOCKER_CALLS")
  fi
  echo "PASS: body E2E cleanup $scenario"
done

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
