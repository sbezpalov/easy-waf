#!/usr/bin/env bash
# Real smoke startup with stand-in service/HTTP/admin probes, never an appliance.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin" "$ROOT/state"
export SMOKE_TEST_ARGS="$ROOT/curl-args"
export SMOKE_TEST_ADMIN_ARGS="$ROOT/admin-args"
cat >"$ROOT/bin/curl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"$SMOKE_TEST_ARGS"
body='{}'
for arg in "$@"; do
  if [[ "$arg" == */api/v1/stats/haproxy ]]; then
    body="${SMOKE_TEST_STATS:-}"
    if [[ -z "$body" ]]; then body='{"frontends":[],"backends":[]}'; fi
  fi
done
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then shift; printf '%s\n' "$body" >"$1"; fi
  shift
done
printf '200'
MOCK
cat >"$ROOT/bin/admin" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"$SMOKE_TEST_ADMIN_ARGS"
exit 0
MOCK
printf '#!/bin/sh\nexit 1\n' >"$ROOT/bin/systemctl"
chmod 0700 "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"
export EASY_WAF_ENV_FILE="$ROOT/config.env"
export EASY_WAF_STATE_DIR="$ROOT/state"
export EASY_WAF_ADMIN_BIN="$ROOT/bin/admin"
export EASY_WAF_API_BASE='https://fixture.example'
export EASY_WAF_SMOKE_SKIP_APPLY=1
unset EASY_WAF_SMOKE_USER EASY_WAF_SMOKE_PASSWORD EASY_WAF_SMOKE_MMDB
marker="$ROOT/executed"
expected="literal-token-\$not_expanded;still-data-123456789"
printf 'UNUSED=%s\nEASY_WAF_ADMIN_TOKEN=%s\n' "\$(touch \"$marker\")" "$expected" >"$EASY_WAF_ENV_FILE"
# Appliance checks intentionally fail in this non-appliance fixture.
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
[[ ! -e "$marker" ]] || { echo 'FAIL: env file executed shell code' >&2; exit 1; }
grep -qxF "Authorization: Bearer $expected" "$SMOKE_TEST_ARGS" || { echo 'FAIL: token not preserved literally' >&2; exit 1; }
if ! grep -qxF -- '-env-file' "$SMOKE_TEST_ADMIN_ARGS" ||
  ! grep -qxF "$EASY_WAF_ENV_FILE" "$SMOKE_TEST_ADMIN_ARGS" ||
  ! grep -qxF "$EASY_WAF_STATE_DIR" "$SMOKE_TEST_ADMIN_ARGS"; then
  echo 'FAIL: doctor lost selected configuration' >&2; exit 1
fi
printf 'EASY_WAF_ADMIN_TOKEN=\n' >"$EASY_WAF_ENV_FILE"
export EASY_WAF_ADMIN_TOKEN='stale-process-token-123456789'
: >"$SMOKE_TEST_ARGS"
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
if grep -qF 'Authorization: Bearer stale-process-token' "$SMOKE_TEST_ARGS"; then
  echo 'FAIL: empty file token used stale process token' >&2; exit 1
fi
: >"$EASY_WAF_ENV_FILE"
: >"$SMOKE_TEST_ARGS"
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qxF "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" "$SMOKE_TEST_ARGS" || { echo 'FAIL: missing-key fallback lost' >&2; exit 1; }
grep -qF 'PASS  HAProxy runtime stats available after reload' "$ROOT/output" || { echo 'FAIL: valid runtime stats rejected' >&2; exit 1; }
export SMOKE_TEST_STATS='{"frontends":[],"backends":[],"error":"fixture socket missing"}'
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qF 'FAIL  HAProxy runtime stats unavailable after reload' "$ROOT/output" || { echo 'FAIL: HTTP 200 collector error accepted' >&2; exit 1; }
echo 'OK: smoke env stays data'
