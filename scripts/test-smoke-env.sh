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
code=200
url=''
for arg in "$@"; do
  if [[ "$arg" == https://fixture.example/* ]]; then url="$arg"; fi
  if [[ "$arg" == */api/v1/stats/haproxy ]]; then
    body="${SMOKE_TEST_STATS:-}"
    if [[ -z "$body" ]]; then body='{"frontends":[],"backends":[]}'; fi
  fi
  if [[ "$arg" == */api/v1/geoip/lookup\?* ]]; then
    code="${SMOKE_TEST_GEOIP_STATUS:-200}"
    body='{"ip":"8.8.8.8","country":"US","cached":false}'
  fi
done
case "$url" in
  */api/v1/auth/login|*/api/v1/auth/confirm) body='{"token":"fixture-session"}' ;;
  */api/v1/auth/logout) : >"$SMOKE_TEST_LOGOUT_MARKER" ;;
  */api/v1/auth/me) if [[ -e "$SMOKE_TEST_LOGOUT_MARKER" ]]; then code=401; fi ;;
esac
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then shift; printf '%s\n' "$body" >"$1"; fi
  shift
done
printf '%s' "$code"
if [[ -n "${SMOKE_TEST_TRANSPORT_PATH:-}" && "$url" == *"$SMOKE_TEST_TRANSPORT_PATH" ]]; then
  exit 18
fi
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
export SMOKE_TEST_LOGOUT_MARKER="$ROOT/logged-out"
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
unset SMOKE_TEST_STATS
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qF 'PASS  GeoIP lookup 8.8.8.8' "$ROOT/output" || { echo 'FAIL: successful GeoIP lookup rejected' >&2; exit 1; }
for code in 502 401 000; do
  export SMOKE_TEST_GEOIP_STATUS="$code"
  bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
  grep -qF "FAIL  GeoIP lookup -> $code;" "$ROOT/output" || { echo "FAIL: GeoIP $code did not fail smoke" >&2; exit 1; }
  if grep -qF 'SKIP  GeoIP lookup' "$ROOT/output"; then
    echo "FAIL: GeoIP $code silently skipped" >&2
    exit 1
  fi
done
unset SMOKE_TEST_GEOIP_STATUS

assert_failed_transfer() {
  local route="$1" message="$2"
  SMOKE_TEST_TRANSPORT_PATH="$route" bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
  if ! grep -qF "$message" "$ROOT/output"; then
    echo "FAIL: incomplete response accepted for $route" >&2
    exit 1
  fi
}
assert_failed_transfer '/health' 'FAIL  GET /health -> 000'
assert_failed_transfer '/api/v1/status' 'FAIL  GET /api/v1/status -> 000'
assert_failed_transfer '/api/v1/stats/haproxy' 'FAIL  HAProxy runtime stats unavailable after reload'
assert_failed_transfer '/api/v1/geoip/lookup?ip=8.8.8.8&nocache=1' 'FAIL  GeoIP lookup -> 000'

export EASY_WAF_SMOKE_USER=fixture EASY_WAF_SMOKE_PASSWORD=fixture
export EASY_WAF_SMOKE_MMDB="$ROOT/fixture.mmdb"
: >"$EASY_WAF_SMOKE_MMDB"
: >"$SMOKE_TEST_ARGS"
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qF 'PASS  logout revokes the session server-side' "$ROOT/output"
for expected_arg in --connect-timeout --max-time 5 30 120; do
  grep -qxF -- "$expected_arg" "$SMOKE_TEST_ARGS" || { echo "FAIL: missing HTTP timeout argument $expected_arg" >&2; exit 1; }
done
rm -f "$SMOKE_TEST_LOGOUT_MARKER"
assert_failed_transfer '/api/v1/auth/logout' 'FAIL  logout verification failed: /auth/me 200 -> /auth/logout 000 -> /auth/me 401'
assert_failed_transfer '/api/v1/geoip/database' 'FAIL  GeoIP upload request failed'
echo 'OK: smoke env stays data; HTTP failures are not skipped'
