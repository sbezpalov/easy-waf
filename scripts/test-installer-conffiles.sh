#!/usr/bin/env bash
# Real APT/dpkg, dummy payloads and private package state; no host changes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_BIN="${DOCKER_BIN:-docker}"
image="${EASY_WAF_CONFFILE_TEST_IMAGE:-ubuntu:24.04}"
command -v "$DOCKER_BIN" >/dev/null || { echo "Docker not found: $DOCKER_BIN" >&2; exit 1; }
docker_root="$ROOT"
if command -v cygpath >/dev/null 2>&1; then docker_root="$(cygpath -m "$ROOT")"; fi
export MSYS_NO_PATHCONV=1
"$DOCKER_BIN" run --rm --pull never --user 0:0 --network none --no-healthcheck \
  --label easy-waf.fixture=installer-conffiles --read-only --cap-drop ALL \
  --security-opt no-new-privileges --memory 256m --pids-limit 128 \
  --tmpfs /tmp:rw,exec,mode=1777 \
  --mount "type=bind,source=${docker_root},target=/repo,readonly" \
  --entrypoint /bin/bash "$image" /repo/scripts/testdata/installer-conffiles.sh
