#!/usr/bin/env bash
# Run the real root backup against fake leaf commands in a disposable Linux OS.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_BIN="${DOCKER_BIN:-docker}"
image="${EASY_WAF_BACKUP_TEST_IMAGE:-ubuntu:24.04}"
command -v "$DOCKER_BIN" >/dev/null || { echo "Docker not found: $DOCKER_BIN" >&2; exit 1; }
docker_root="$ROOT"
if command -v cygpath >/dev/null 2>&1; then
  docker_root="$(cygpath -m "$ROOT")"
fi
export MSYS_NO_PATHCONV=1
"$DOCKER_BIN" run --rm --pull never --user 0:0 --network none --no-healthcheck \
  --label easy-waf.fixture=backup-publication --read-only --cap-drop ALL \
  --security-opt no-new-privileges --memory 128m --pids-limit 128 \
  --tmpfs /tmp:rw,exec,mode=1777 --tmpfs /etc/easy-waf:rw,mode=0700 \
  --mount "type=bind,source=${docker_root},target=/repo,readonly" \
  --entrypoint /bin/bash "$image" -c 'bash /repo/scripts/testdata/backup-publication.sh && bash /repo/scripts/testdata/restore-permissions.sh && bash /repo/scripts/testdata/restore-lock.sh'
