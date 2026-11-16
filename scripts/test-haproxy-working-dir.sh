#!/usr/bin/env bash
# Actual drop-in script with private OS paths and fake privileged leaf commands.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_BIN="${DOCKER_BIN:-docker}"
image="${EASY_WAF_HAPROXY_CWD_TEST_IMAGE:-ubuntu:24.04}"
command -v "$DOCKER_BIN" >/dev/null || { echo "Docker not found: $DOCKER_BIN" >&2; exit 1; }
docker_root="$ROOT"
if command -v cygpath >/dev/null 2>&1; then docker_root="$(cygpath -m "$ROOT")"; fi
export MSYS_NO_PATHCONV=1
"$DOCKER_BIN" run --rm --pull never --user 0:0 --network none --no-healthcheck \
  --label easy-waf.fixture=haproxy-working-dir --read-only --cap-drop ALL \
  --security-opt no-new-privileges --memory 128m --pids-limit 128 \
  --tmpfs /tmp:rw,exec,mode=1777 --tmpfs /usr/sbin:rw,exec,mode=0755 \
  --tmpfs /etc/systemd/system:rw,mode=0755 --tmpfs /etc/tmpfiles.d:rw,mode=0755 \
  --tmpfs /run/haproxy:rw,mode=0755 \
  --mount "type=bind,source=${docker_root},target=/repo,readonly" \
  --entrypoint /bin/bash "$image" /repo/scripts/testdata/haproxy-working-dir.sh
