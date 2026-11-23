#!/usr/bin/env bash
# Real smoke startup with stand-in service/HTTP/admin probes, never an appliance.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin" "$ROOT/state"
export SMOKE_TEST_ARGS="$ROOT/curl-args"
export SMOKE_TEST_ADMIN_ARGS="$ROOT/admin-args"
export SMOKE_TEST_HEADERS="$ROOT/headers"
export SMOKE_TEST_CHILD_CREDENTIALS="$ROOT/child-credentials"
cat >"$ROOT/bin/curl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"$SMOKE_TEST_ARGS"
if [[ -v EASY_WAF_ADMIN_TOKEN || -v EASY_WAF_SMOKE_PASSWORD || -v EASY_WAF_SMOKE_TOTP_CODE ]]; then
  : >"$SMOKE_TEST_CHILD_CREDENTIALS"
fi
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
  */health/ready) code="${SMOKE_TEST_READY_STATUS:-200}" ;;
  */api/v1/auth/login) body='{"token":"fixture-session"}' ;;
  */api/v1/auth/confirm) body='{"token":"fixture-step-up"}' ;;
  */api/v1/auth/logout) : >"$SMOKE_TEST_LOGOUT_MARKER" ;;
  */api/v1/auth/me) if [[ -e "$SMOKE_TEST_LOGOUT_MARKER" ]]; then code=401; fi ;;
esac
while [[ $# -gt 0 ]]; do
  if [[ "$1" == -o ]]; then shift; printf '%s\n' "$body" >"$1"; fi
  if [[ "$1" == -H && "$2" == @* ]]; then
    IFS= read -r authorization <"${2#@}" || exit 90
    printf '%s|%s\n' "$url" "$authorization" >>"$SMOKE_TEST_HEADERS"
  fi
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
if [[ "$1" == --version ]]; then
  printf 'easy-waf-admin %s\n' "${SMOKE_TEST_ADMIN_VERSION:-1.6.1}"
fi
exit 0
MOCK
cat >"$ROOT/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == show && "${!#}" == easy-waf-backup.timer && -n "${SMOKE_TEST_TIMER:-}" ]]; then
  printf '%s\n' "$SMOKE_TEST_TIMER"
  exit 0
fi
exit 1
MOCK
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
assert_timer() {
  local properties="$1" message="$2"
  SMOKE_TEST_TIMER="$properties" bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
  if ! grep -qF "$message" "$ROOT/output"; then
    echo "FAIL: missing backup timer report: $message" >&2
    exit 1
  fi
}
assert_timer $'LoadState=loaded\nActiveState=inactive\nSubState=dead\nUnitFileState=enabled' \
  'FAIL  easy-waf-backup.timer is enabled but inactive'
assert_timer $'LoadState=loaded\nActiveState=active\nSubState=waiting\nUnitFileState=enabled\nNextElapseUSecRealtime=Wed 2026-11-18 03:45:00 UTC' \
  'PASS  easy-waf-backup.timer active with a scheduled run'
assert_timer $'LoadState=loaded\nActiveState=active\nSubState=waiting\nUnitFileState=enabled-runtime\nNextElapseUSecMonotonic=2h 30min' \
  'PASS  easy-waf-backup.timer active with a scheduled run'
assert_timer $'LoadState=loaded\nActiveState=active\nSubState=elapsed\nUnitFileState=enabled\nNextElapseUSecRealtime=n/a\nNextElapseUSecMonotonic=0' \
  'FAIL  easy-waf-backup.timer is active but has no next run'
assert_timer $'LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled' \
  'PASS  easy-waf-backup.timer active (backup running)'
assert_timer $'LoadState=loaded\nActiveState=inactive\nUnitFileState=disabled' \
  'SKIP  easy-waf-backup.timer is disabled'
assert_timer $'LoadState=masked\nActiveState=inactive\nUnitFileState=masked' \
  'SKIP  easy-waf-backup.timer is masked'
assert_timer $'LoadState=not-found\nActiveState=inactive' \
  'SKIP  easy-waf-backup.timer not installed'
# Appliance checks intentionally fail in this non-appliance fixture.
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
[[ ! -e "$marker" ]] || { echo 'FAIL: env file executed shell code' >&2; exit 1; }
if grep -qF "Authorization: Bearer $expected" "$SMOKE_TEST_ARGS"; then
  echo 'FAIL: bearer token is present in curl command arguments' >&2; exit 1
fi
grep -qxF "https://fixture.example/api/v1/status|Authorization: Bearer $expected" "$SMOKE_TEST_HEADERS" ||
  { echo 'FAIL: file token not preserved literally' >&2; exit 1; }
if ! grep -qxF -- '-env-file' "$SMOKE_TEST_ADMIN_ARGS" ||
  ! grep -qxF "$EASY_WAF_ENV_FILE" "$SMOKE_TEST_ADMIN_ARGS" ||
  ! grep -qxF "$EASY_WAF_STATE_DIR" "$SMOKE_TEST_ADMIN_ARGS"; then
  echo 'FAIL: doctor lost selected configuration' >&2; exit 1
fi
printf 'EASY_WAF_ADMIN_TOKEN=\n' >"$EASY_WAF_ENV_FILE"
export EASY_WAF_ADMIN_TOKEN='stale-process-token-123456789'
: >"$SMOKE_TEST_HEADERS"
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
if grep -qF 'Authorization: Bearer stale-process-token' "$SMOKE_TEST_HEADERS"; then
  echo 'FAIL: empty file token used stale process token' >&2; exit 1
fi
: >"$EASY_WAF_ENV_FILE"
: >"$SMOKE_TEST_HEADERS"
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qxF "https://fixture.example/api/v1/status|Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" "$SMOKE_TEST_HEADERS" ||
  { echo 'FAIL: missing-key fallback lost' >&2; exit 1; }
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
assert_failed_transfer '/health/ready' 'FAIL  GET /health/ready -> 000'
SMOKE_TEST_READY_STATUS=503 bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qF 'PASS  GET /health -> 200' "$ROOT/output"
grep -qF 'FAIL  GET /health/ready -> 503' "$ROOT/output"
assert_failed_transfer '/api/v1/status' 'FAIL  GET /api/v1/status -> 000'
assert_failed_transfer '/api/v1/stats/haproxy' 'FAIL  HAProxy runtime stats unavailable after reload'
assert_failed_transfer '/api/v1/geoip/lookup?ip=8.8.8.8&nocache=1' 'FAIL  GeoIP lookup -> 000'

expected_status=0
: >"$SMOKE_TEST_ADMIN_ARGS"
EASY_WAF_SMOKE_EXPECTED_VERSION=1.6.1 SMOKE_TEST_ADMIN_VERSION=1.6.0 EASY_WAF_SMOKE_SKIP_APPLY=0 \
  bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || expected_status=$?
[[ "$expected_status" == 1 ]]
grep -qF 'FAIL  easy-waf-admin does not report expected version 1.6.1' "$ROOT/output"
grep -qF 'FAIL  easy-waf-api not installed' "$ROOT/output"
grep -qxF -- '--version' "$SMOKE_TEST_ADMIN_ARGS"
if grep -qxF 'apply-edge' "$SMOKE_TEST_ADMIN_ARGS"; then
  echo 'FAIL: expected-release mismatch reached the HAProxy apply step' >&2
  exit 1
fi

# On Linux, use the actual /proc executable and a copy so that different
# inodes with identical bytes are accepted and stale binaries are rejected.
if [[ -r "/proc/$$/exe" ]]; then
  (
    binary_probe="$(sed -n '/^check_running_binary() {$/,/^}$/p' "$SCRIPT_DIR/smoke-appliance.sh")"
    [[ -n "$binary_probe" ]]
    eval "$binary_probe"
    fixture_pid="$$"
    # shellcheck disable=SC2317,SC2329
    systemctl() { printf '%s\n' "$fixture_pid"; }
    # shellcheck disable=SC2317,SC2329
    pass() { printf 'PASS %s\n' "$*"; }
    # shellcheck disable=SC2317,SC2329
    fail() { printf 'FAIL %s\n' "$*"; }
    cp "/proc/$fixture_pid/exe" "$ROOT/installed"
    [[ "$(check_running_binary easy-waf-api "$ROOT/installed")" == 'PASS easy-waf-api is running the installed binary' ]]
    printf 'new version\n' >"$ROOT/installed"
    [[ "$(check_running_binary easy-waf-api "$ROOT/installed")" == "FAIL easy-waf-api running binary does not match $ROOT/installed" ]]
    fixture_pid=0
    [[ "$(check_running_binary easy-waf-api "$ROOT/installed")" == 'FAIL easy-waf-api is active but its main PID could not be verified' ]]
  )
fi

export EASY_WAF_SMOKE_USER=fixture EASY_WAF_SMOKE_PASSWORD=fixture-password EASY_WAF_SMOKE_TOTP_CODE=123456
export EASY_WAF_SMOKE_MMDB="$ROOT/fixture.mmdb"
: >"$EASY_WAF_SMOKE_MMDB"
: >"$SMOKE_TEST_ARGS"
: >"$SMOKE_TEST_HEADERS"
bash "$SCRIPT_DIR/smoke-appliance.sh" >"$ROOT/output" 2>&1 || true
grep -qF 'PASS  logout revokes the session server-side' "$ROOT/output"
grep -qxF 'https://fixture.example/api/v1/auth/confirm|Authorization: Bearer fixture-session' "$SMOKE_TEST_HEADERS"
grep -qxF 'https://fixture.example/api/v1/geoip/database|Authorization: Bearer fixture-step-up' "$SMOKE_TEST_HEADERS"
grep -qxF 'https://fixture.example/api/v1/auth/logout|Authorization: Bearer fixture-session' "$SMOKE_TEST_HEADERS"
if grep -qE 'Authorization: Bearer|fixture-password|fixture-session|fixture-step-up' "$SMOKE_TEST_ARGS" ||
   [[ -e "$SMOKE_TEST_CHILD_CREDENTIALS" ]]; then
  echo 'FAIL: credentials passed in arguments or environment of curl' >&2
  exit 1
fi
for expected_arg in --connect-timeout --max-time 5 30 120; do
  grep -qxF -- "$expected_arg" "$SMOKE_TEST_ARGS" || { echo "FAIL: missing HTTP timeout argument $expected_arg" >&2; exit 1; }
done
rm -f "$SMOKE_TEST_LOGOUT_MARKER"
assert_failed_transfer '/api/v1/auth/logout' 'FAIL  logout verification failed: /auth/me 200 -> /auth/logout 000 -> /auth/me 401'
assert_failed_transfer '/api/v1/geoip/database' 'FAIL  GeoIP upload request failed'
echo 'OK: smoke env stays data; HTTP failures are not skipped'
