#!/usr/bin/env bash
# Real broker -> APT -> dpkg -> postinst -> systemd restart, in a disposable OS.
# Needs a Linux Docker engine capable of private cgroup delegation and SYS_ADMIN
# for nested service mount namespaces. No privileged mode, host cgroup bind,
# host PID/network or Docker socket is used. Runtime network is disabled.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_BIN="${GO_BIN:-go}"
DOCKER_BIN="${DOCKER_BIN:-docker}"
command -v "$GO_BIN" >/dev/null || { echo "Go not found: $GO_BIN" >&2; exit 1; }
command -v "$DOCKER_BIN" >/dev/null || { echo "Docker not found: $DOCKER_BIN" >&2; exit 1; }
WORK="$(mktemp -d)"
CID=''
OWN_IMAGE=''
cleanup() {
  local result=$?
  if [[ -n "$CID" ]]; then
    if ((result)); then
      "$DOCKER_BIN" logs --tail 50 "$CID" >&2 || true
    fi
    "$DOCKER_BIN" rm -f "$CID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$OWN_IMAGE" ]]; then
    "$DOCKER_BIN" image rm "$OWN_IMAGE" >/dev/null 2>&1 || true
  fi
  rm -f "$WORK/easy-waf-hostd" "$WORK/hostd.test"
  rmdir "$WORK" || true
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 0755 "$WORK"
cd "$ROOT"
case "$("$DOCKER_BIN" info --format '{{.Architecture}}')" in
  x86_64 | amd64) target_arch=amd64 ;;
  aarch64 | arm64) target_arch=arm64 ;;
  *) echo 'Only amd64/arm64 Linux Docker engines are supported' >&2; exit 1 ;;
esac
if [[ "$("$DOCKER_BIN" info --format '{{.OSType}}')" != linux ]]; then
  echo 'Switch Docker Desktop to Linux containers' >&2; exit 1
fi
CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" "$GO_BIN" build -o "$WORK/easy-waf-hostd" ./cmd/easy-waf-hostd
CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" "$GO_BIN" test -tags=integration -c -o "$WORK/hostd.test" ./internal/hostd

image="${EASY_WAF_PACKAGE_E2E_IMAGE:-}"
if [[ -z "$image" ]]; then
  OWN_IMAGE="easy-waf-package-e2e:fixture-$(date +%s)-${RANDOM}"
  "$DOCKER_BIN" build --pull=false \
    --build-arg "BASE_IMAGE=${EASY_WAF_PACKAGE_E2E_BASE_IMAGE:-ubuntu:24.04}" \
    -t "$OWN_IMAGE" "$ROOT/scripts/testdata/package-restart"
  image="$OWN_IMAGE"
fi
# Avoid Git Bash rewriting container paths; normalize only the two host paths.
docker_root="$ROOT"
docker_work="$WORK"
if command -v cygpath >/dev/null 2>&1; then
  docker_root="$(cygpath -m "$ROOT")"
  docker_work="$(cygpath -m "$WORK")"
fi
export MSYS_NO_PATHCONV=1
CID="$("$DOCKER_BIN" run --pull=never --detach --no-healthcheck --network none --cgroupns private \
  --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
  --label easy-waf.fixture=package-systemd --memory 512m --pids-limit 256 \
  --tmpfs /run:rw,nosuid,size=32m --tmpfs /run/lock:rw,nosuid,size=16m \
  --mount "type=bind,source=${docker_root},target=/repo,readonly" \
  --mount "type=bind,source=${docker_work},target=/inputs,readonly" \
  --entrypoint /usr/local/libexec/easy-waf-package-fixture-boot "$image")"
ready=0
for ((attempt=0; attempt<40; attempt++)); do
  if "$DOCKER_BIN" exec "$CID" systemctl is-active --quiet easy-waf-fixture.target; then
    ready=1
    break
  fi
  if [[ "$("$DOCKER_BIN" inspect --format '{{.State.Running}}' "$CID")" != true ]]; then
    break
  fi
  sleep 0.25
done
((ready)) || { echo 'Fixture systemd did not reach its target' >&2; exit 1; }
"$DOCKER_BIN" exec --env RUN_PACKAGE_RESTART_INTEGRATION=1 "$CID" \
  /inputs/hostd.test -test.run '^TestPackageRestartSystemdLifecycle$' -test.v -test.timeout 170s
