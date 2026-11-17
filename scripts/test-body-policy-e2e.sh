#!/usr/bin/env bash
# End-to-end proof of the multipart block and body limit, evasions included, on
# the config easy-waf generates: HAProxy 2.8 (the Ubuntu 24.04 series) and the
# app-body-policy golden, changed only to address the containers. Needs Docker
# and network access for images; runs in the nightly E2E workflow.
#
#   bash scripts/test-body-policy-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN="$ROOT/internal/haproxy/testdata/golden"
CURL_IMAGE=curlimages/curl:8.10.1

WORK="$(mktemp -d)"
network_name="easywaf-body-e2e-${WORK##*/}"
network_id=''
app_id=''
haproxy_id=''
remove_stack() {
  local id
  for id in "$haproxy_id" "$app_id"; do
    if [[ -n "$id" ]]; then
      docker rm -f "$id" >/dev/null 2>&1 || true
    fi
  done
  if [[ -n "$network_id" ]]; then
    docker network rm "$network_id" >/dev/null 2>&1 || true
  fi
}
trap 'remove_stack; rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Docker needs a native host bind path, while /cfg and executable arguments
# must remain Linux paths when launched from Git Bash on Windows.
docker_work="$WORK"
if command -v cygpath >/dev/null 2>&1; then
  docker_work="$(cygpath -m "$WORK")"
fi
export MSYS_NO_PATHCONV=1

network_id="$(docker network create --subnet 10.78.0.0/24 "$network_name")"
# Keep each ID before starting so a failed start still cleans up the container.
app_id="$(docker create --network "$network_id" --ip 10.78.0.30 traefik/whoami:v1.10 --port 80)"
docker start "$app_id" >/dev/null

sed -E \
  -e '/^[[:space:]]*(user|group) haproxy$/d' \
  -e 's#stats socket [^ ]+#stats socket /tmp/haproxy.sock#' \
  -e 's#config testdata/golden/spoe/crowdsec-vendor\.cfg#config /cfg/crowdsec.cfg#' \
  -e 's#server s1 192\.168\.1\.60:80 .*#server s1 10.78.0.30:80#' \
  -e 's#^([[:space:]]*)bind \*:80$#\1bind *:80\n\1bind *:81 proto h2#' \
  "$GOLDEN/app-body-policy.cfg" >"$WORK/haproxy.cfg"
cp "$GOLDEN/spoe/crowdsec-vendor.cfg" "$WORK/crowdsec.cfg"
chmod -R a+rX "$WORK"

haproxy_id="$(docker create --network "$network_id" --ip 10.78.0.40 --ulimit nofile=200000:200000 \
  --mount "type=bind,source=${docker_work},target=/cfg,readonly" \
  haproxy:2.8 haproxy -f /cfg/haproxy.cfg)"
docker start "$haproxy_id" >/dev/null
sleep 3
[[ "$(docker inspect --format '{{.State.Running}}' "$haproxy_id")" == true ]] || {
  docker logs "$haproxy_id" 2>&1 | tail -20
  exit 1
}

# Runs in one curl container: prints "<want> <got> <description>" per case.
cat >"$WORK/cases.sh" <<'EOF'
head -c 500 /dev/zero >/tmp/small
head -c 5000 /dev/zero >/tmp/big
base=http://10.78.0.40
check() { # want description host curl-args...
  want="$1" desc="$2" host="$3"
  shift 3
  got="$(curl -s -o /dev/null -w '%{http_code}' -m 8 -H "Host: $host" "$@")" || true
  echo "$want $got $desc"
}
php=php.example.local up=up.example.local open=open.example.local

check 200 "plain GET" $php $base/
check 200 "form post" $php -d a=1 $base/
check 200 "no policy: multipart passes" $open -F a=1 $base/
check 200 "no policy: chunked passes" $open -H 'Transfer-Encoding: chunked' --data-binary @/tmp/big $base/

check 415 "multipart" $php -F a=1 $base/
check 415 "multipart, upper case" $php -H 'Content-Type: MULTIPART/FORM-DATA; boundary=x' -d x $base/
check 415 "multipart, second value" $php -H 'Content-Type: text/plain, multipart/form-data' -d x $base/
check 415 "multipart, second header" $php -H 'Content-Type: text/plain' -H 'Content-Type: multipart/form-data' -d x $base/
check 415 "multipart, leading spaces" $php -H 'Content-Type:    multipart/form-data' -d x $base/
check 415 "multipart, PUT" $php -X PUT -F a=1 $base/
check 415 "multipart, HTTP/2" $php --http2-prior-knowledge -F a=1 http://10.78.0.40:81/

check 200 "allowed path" $up -F a=1 $base/upload/x
check 200 "allowed path, exact" $up -F a=1 $base/upload
check 415 "not an allowed path" $up -F a=1 $base/x
check 415 "same prefix, other script" $up -F a=1 $base/upload.php
check 415 "same prefix, other directory" $up -F a=1 $base/uploads/x.php
check 415 "allowed path, dots" $up --path-as-is -F a=1 $base/upload/../x.php
check 415 "allowed path, encoded dots" $up --path-as-is -F a=1 $base/upload/%2e%2e/x.php
check 415 "allowed path, mixed dots" $up --path-as-is -F a=1 $base/upload/.%2E/x.php

check 200 "body within limit" $up --data-binary @/tmp/small $base/
check 413 "body over limit" $up --data-binary @/tmp/big $base/
check 413 "over limit, HTTP/2" $up --http2-prior-knowledge --data-binary @/tmp/big http://10.78.0.40:81/
check 411 "chunked" $up -H 'Transfer-Encoding: chunked' --data-binary @/tmp/big $base/
check 411 "chunked, mixed case" $up -H 'TrAnSfEr-EnCoDiNg: ChUnKeD' --data-binary @/tmp/small $base/
check 411 "chunked and Content-Length" $up -H 'Transfer-Encoding: chunked' -H 'Content-Length: 10' --data-binary @/tmp/big $base/
check 411 "HTTP/2, no length" $up --http2-prior-knowledge -T - -X POST http://10.78.0.40:81/ </tmp/big
EOF

# Process substitution would hide a failed Docker client/container and let an
# empty or truncated suite report success. Collect only a completed runner's
# output, then require one result for every check in the generated case script.
if ! docker run --rm -i --network "$network_id" --entrypoint sh "$CURL_IMAGE" -s <"$WORK/cases.sh" >"$WORK/results"; then
  echo 'FAIL: body policy case runner did not complete' >&2
  exit 1
fi
expected_cases="$(grep -c '^check ' "$WORK/cases.sh")"
cases=0
failures=0
while read -r want got desc; do
  cases=$((cases + 1))
  if [[ "$want" == "$got" ]]; then
    echo "PASS: $desc ($got)"
  else
    echo "FAIL: $desc: want $want, got $got"
    failures=$((failures + 1))
  fi
done <"$WORK/results"

if ((cases != expected_cases)); then
  echo "FAIL: incomplete body policy results: got $cases, expected $expected_cases" >&2
  exit 1
fi

if ((failures)); then
  echo "---- haproxy log"
  docker logs --tail 20 "$haproxy_id" 2>&1 | cut -c1-200
  exit 1
fi
echo "OK: multipart block and body limit hold"
