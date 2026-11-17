#!/usr/bin/env bash
# Exercise the real launcher with a recording Docker stub. No engine needed.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export DOCKER_CALLS="$work/calls"
export PATH="$work:$PATH"
cat >"$work/docker" <<'STUB'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >>"$DOCKER_CALLS"
case "$1 ${2:-}" in
  'network create')
    [[ "$DOCKER_CASE" != subnet-conflict ]] || exit 41
    echo owned-network
    ;;
  'create --network') echo owned-container ;;
  'start owned-container') exit 42 ;;
  'rm -f' | 'network rm') ;;
  *) exit 99 ;;
esac
STUB
chmod +x "$work/docker"

run_case() {
  local rc=0
  : >"$DOCKER_CALLS"
  DOCKER_CASE="$1" bash "$ROOT/scripts/test-crowdsec-e2e.sh" >"$work/result" 2>&1 || rc=$?
  if [[ "$rc" != "$2" ]]; then
    cat "$work/result" >&2
    printf 'Expected exit %s in %s, got %s\n' "$2" "$1" "$rc" >&2
    exit 1
  fi
}

run_case subnet-conflict 41
[[ "$(wc -l <"$DOCKER_CALLS")" -eq 1 ]]
grep -q '^network create ' "$DOCKER_CALLS"
echo 'PASS: failed network creation leaves other Docker resources alone'

run_case start-failure 42
grep -qx 'start owned-container' "$DOCKER_CALLS"
diff -u <(printf '%s\n' 'rm -f owned-container' 'network rm owned-network') \
  <(grep -E '^(rm |network rm )' "$DOCKER_CALLS")
echo 'PASS: failed start cleans up only the IDs returned to this launch'
