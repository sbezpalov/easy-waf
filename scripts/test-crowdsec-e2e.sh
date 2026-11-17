#!/usr/bin/env bash
# End-to-end proof that a CrowdSec decision blocks traffic through the HAProxy
# config easy-waf generates: real LAPI, real SPOA bouncer, HAProxy 2.8 (the
# Ubuntu 24.04 series) and the http-only golden config, changed only to address
# the containers. Needs Docker and network access for images; runs in nightly E2E.
#
#   bash scripts/test-crowdsec-e2e.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN="$ROOT/internal/haproxy/testdata/golden"
BOUNCER_KEY=e2e-bouncer-key-0123456789abcdef
HOST_HEADER="$(sed -n 's/.*acl http_app_ho1_host hdr(host) -i \([^ ]*\).*/\1/p' "$GOLDEN/http-only-app.cfg" | head -1)"
[[ -n "$HOST_HEADER" ]] || { echo "could not read the published host from the golden config" >&2; exit 1; }

WORK="$(mktemp -d)"
NET="easywaf-cs-e2e-${WORK##*/}"
network_id=''
container_id=''
containers=()
remove_stack() {
  if ((${#containers[@]})); then
    docker rm -f "${containers[@]}" >/dev/null 2>&1 || true
  fi
  if [[ -n "$network_id" ]]; then
    docker network rm "$network_id" >/dev/null 2>&1 || true
  fi
}
trap 'remove_stack; rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Normalize only the host bind source; keep container arguments as Linux paths
# when this launcher is invoked through Git Bash on Windows.
docker_work="$WORK"
if command -v cygpath >/dev/null 2>&1; then
  docker_work="$(cygpath -m "$WORK")"
fi
export MSYS_NO_PATHCONV=1

# Keep the ID before starting: Docker can create a container successfully
# and then fail to start it. Cleanup must still remove that container.
start_container() {
  container_id="$(docker create --network "$network_id" "$@")"
  containers+=("$container_id")
  docker start "$container_id" >/dev/null
}

failures=0
check() { # description want got
  if [[ "$2" == "$3" ]]; then
    echo "PASS: $1 ($3)"
  else
    echo "FAIL: $1: want $2, got $3"
    failures=$((failures + 1))
  fi
}

# status <client-ip>: the HTTP status that client gets through HAProxy.
status() {
  docker run --rm --network "$network_id" --ip "$1" curlimages/curl:8.10.1 \
    -s -o /dev/null -w '%{http_code}' -m 10 -H "Host: $HOST_HEADER" http://10.77.0.40/
}

network_id="$(docker network create --subnet 10.77.0.0/24 "$NET")"

start_container --ip 10.77.0.10 \
  -e DISABLE_ONLINE_API=true -e CROWDSEC_BYPASS_DB_VOLUME_CHECK=true \
  -e "BOUNCER_KEY_SPOA=$BOUNCER_KEY" crowdsecurity/crowdsec:latest
lapi="$container_id"

for _ in $(seq 1 60); do
  docker exec "$lapi" cscli lapi status >/dev/null 2>&1 && break
  sleep 2
done
docker exec "$lapi" cscli lapi status >/dev/null

cat >"$WORK/bouncer.yaml" <<EOF
log_mode: stdout
log_level: info
update_frequency: 1s
api_url: http://10.77.0.10:8080/
api_key: $BOUNCER_KEY
listen_tcp: 0.0.0.0:9000
EOF
start_container --ip 10.77.0.20 \
  --mount "type=bind,source=${docker_work}/bouncer.yaml,target=/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml,readonly" \
  crowdsecurity/spoa-bouncer:latest
spoa="$container_id"

start_container --ip 10.77.0.30 traefik/whoami:v1.10 --port 80

sed -E \
  -e '/^[[:space:]]*(user|group) haproxy$/d' \
  -e 's#stats socket [^ ]+#stats socket /tmp/haproxy.sock#' \
  -e 's#config testdata/golden/spoe/crowdsec-vendor\.cfg#config /cfg/crowdsec.cfg#' \
  -e 's#server spoa 127\.0\.0\.1:9000#server spoa 10.77.0.20:9000#' \
  -e 's#server s1 192\.168\.1\.50:80 .*#server s1 10.77.0.30:80#' \
  "$GOLDEN/http-only-app.cfg" >"$WORK/haproxy.cfg"
cp "$GOLDEN/spoe/crowdsec-vendor.cfg" "$WORK/crowdsec.cfg"
chmod -R a+rX "$WORK"

start_container --ip 10.77.0.40 --ulimit nofile=200000:200000 \
  --mount "type=bind,source=${docker_work},target=/cfg,readonly" \
  haproxy:2.8 haproxy -f /cfg/haproxy.cfg
haproxy="$container_id"
sleep 3
[[ "$(docker inspect --format '{{.State.Running}}' "$haproxy")" == true ]] || {
  docker logs "$haproxy" 2>&1 | tail -20
  exit 1
}

BANNED=10.77.0.50
OTHER=10.77.0.51

check "no decision yet: client passes" 200 "$(status "$BANNED")"

docker exec "$lapi" cscli decisions add --ip "$BANNED" --duration 1h --type ban >/dev/null
sleep 4
check "banned client is refused" 403 "$(status "$BANNED")"
check "other client still passes" 200 "$(status "$OTHER")"

docker exec "$lapi" cscli decisions delete --ip "$BANNED" >/dev/null
sleep 4
check "unbanned client passes again" 200 "$(status "$BANNED")"

docker exec "$lapi" cscli decisions add --ip "$BANNED" --duration 1h --type ban >/dev/null
sleep 4
docker stop -t 1 "$spoa" >/dev/null
sleep 1
check "bouncer down: traffic fails open" 200 "$(status "$BANNED")"

if ((failures)); then
  echo "---- bouncer log"; docker logs --tail 20 "$spoa" 2>&1 | cut -c1-200
  echo "---- haproxy log"; docker logs --tail 20 "$haproxy" 2>&1 | cut -c1-200
  exit 1
fi
echo "OK: CrowdSec decisions are enforced"
