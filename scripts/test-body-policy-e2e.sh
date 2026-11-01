#!/usr/bin/env bash
# End-to-end proof of the multipart block and body limit, evasions included, on
# the config easy-waf generates: HAProxy 2.8 (the Ubuntu 24.04 series) and the
# app-body-policy golden, changed only to address the containers. Needs Docker
# and network access for images; not part of CI.
#
#   bash scripts/test-body-policy-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN="$ROOT/internal/haproxy/testdata/golden"
NET=easywaf-body-e2e
NAMES=(body-e2e-app body-e2e-haproxy)
CURL_IMAGE=curlimages/curl:8.10.1

WORK="$(mktemp -d)"
remove_stack() {
  docker rm -f "${NAMES[@]}" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap 'remove_stack; rm -rf "$WORK"' EXIT
remove_stack

docker network create --subnet 10.78.0.0/24 "$NET" >/dev/null
docker run -d --name body-e2e-app --network "$NET" --ip 10.78.0.30 traefik/whoami:v1.10 --port 80 >/dev/null

sed -E \
  -e '/^[[:space:]]*(user|group) haproxy$/d' \
  -e 's#stats socket [^ ]+#stats socket /tmp/haproxy.sock#' \
  -e 's#config testdata/golden/spoe/crowdsec-vendor\.cfg#config /cfg/crowdsec.cfg#' \
  -e 's#server s1 192\.168\.1\.60:80 .*#server s1 10.78.0.30:80#' \
  -e 's#^([[:space:]]*)bind \*:80$#\1bind *:80\n\1bind *:81 proto h2#' \
  "$GOLDEN/app-body-policy.cfg" >"$WORK/haproxy.cfg"
cp "$GOLDEN/spoe/crowdsec-vendor.cfg" "$WORK/crowdsec.cfg"
chmod -R a+rX "$WORK"

docker run -d --name body-e2e-haproxy --network "$NET" --ip 10.78.0.40 -v "$WORK:/cfg:ro" \
  haproxy:2.8 haproxy -f /cfg/haproxy.cfg >/dev/null
sleep 3
docker ps --format '{{.Names}}' | grep -q '^body-e2e-haproxy$' || {
  docker logs body-e2e-haproxy 2>&1 | tail -20
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
check 415 "not an allowed path" $up -F a=1 $base/x
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

failures=0
while read -r want got desc; do
  if [[ "$want" == "$got" ]]; then
    echo "PASS: $desc ($got)"
  else
    echo "FAIL: $desc: want $want, got $got"
    failures=$((failures + 1))
  fi
done < <(docker run --rm -i --network "$NET" --entrypoint sh "$CURL_IMAGE" -s <"$WORK/cases.sh")

if ((failures)); then
  echo "---- haproxy log"
  docker logs --tail 20 body-e2e-haproxy 2>&1 | cut -c1-200
  exit 1
fi
echo "OK: multipart block and body limit hold"
