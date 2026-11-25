#!/usr/bin/env bash
# Post-upgrade smoke test for a running appliance.
#
# Covers what unit tests and CI cannot: a real PostgreSQL, a real HAProxy reload,
# the systemd units as installed, and the upgrade deltas that only show up on a
# host that already had an older version. Run it after installing a new release
# on the pilot host (see docs/DEV_HOST.md) and again on production.
#
# Usage (as root on the appliance):
#   sudo bash scripts/smoke-appliance.sh
#   sudo EASY_WAF_SMOKE_MMDB=/root/GeoLite2-Country.tar.gz bash scripts/smoke-appliance.sh
#   For operator credentials, use the root-shell example in docs/ACCEPTANCE.md.
#
# Read-mostly: the only state-changing steps are a local easy-waf-admin apply-edge
# (what an operator does anyway) and, when a database file is supplied, a GeoIP
# upload. Backup and restore stay out — that is scripts/test-backup-restore.sh,
# and it is destructive.
#
# Environment:
#   EASY_WAF_ENV_FILE       default /etc/easy-waf/easy-waf.env
#   EASY_WAF_STATE_DIR      default /var/lib/easy-waf
#   EASY_WAF_API_BASE       default https://127.0.0.1:8443
#   EASY_WAF_API_CA_CERT    default $STATE/secrets/management.crt
#   EASY_WAF_CURL_INSECURE=1  skip management TLS verification (recovery only)
#   EASY_WAF_SMOKE_MMDB     path to a GeoLite2 .mmdb/.tar.gz to exercise the upload
#   EASY_WAF_SMOKE_USER / EASY_WAF_SMOKE_PASSWORD  operator login for logout and privileged API checks
#   EASY_WAF_SMOKE_TOTP_CODE  current TOTP code when the operator has TOTP enabled
#   EASY_WAF_SMOKE_SKIP_APPLY=1  do not call easy-waf-admin apply-edge
#   EASY_WAF_SMOKE_EXPECTED_VERSION  require this installed release and active daemons before proceeding

set -uo pipefail
umask 077
# These inputs are needed by this shell only.
export -n EASY_WAF_ADMIN_TOKEN EASY_WAF_SMOKE_PASSWORD EASY_WAF_SMOKE_TOTP_CODE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh" || exit 1

STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
ENV_FILE="${EASY_WAF_ENV_FILE:-/etc/easy-waf/easy-waf.env}"
API_BASE="${EASY_WAF_API_BASE:-https://127.0.0.1:8443}"
BASE="${API_BASE%/}"
API_CA_CERT="${EASY_WAF_API_CA_CERT:-${STATE}/secrets/management.crt}"
ADMIN_BIN="${EASY_WAF_ADMIN_BIN:-/usr/sbin/easy-waf-admin}"
EXPECTED_VERSION="${EASY_WAF_SMOKE_EXPECTED_VERSION:-}"
if [[ -n "$EXPECTED_VERSION" && ! "$EXPECTED_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
  echo 'ERROR: EASY_WAF_SMOKE_EXPECTED_VERSION must be a release version such as 1.6.1' >&2
  exit 2
fi

pass_n=0
fail_n=0
skip_n=0

pass() {
  echo "  PASS  $*"
  pass_n=$((pass_n + 1))
}
fail() {
  echo "  FAIL  $*" >&2
  fail_n=$((fail_n + 1))
}
skip() {
  echo "  SKIP  $*"
  skip_n=$((skip_n + 1))
}
section() { echo; echo "== $* =="; }

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

command -v curl &>/dev/null || {
  echo "ERROR: curl required" >&2
  exit 2
}
[[ -f "$ENV_FILE" ]] || {
  echo "ERROR: $ENV_FILE not found — is this an appliance?" >&2
  exit 2
}

if ! SMOKE_TMPDIR="$(mktemp -d)"; then
  echo "ERROR: cannot create private smoke scratch directory" >&2
  exit 2
fi
trap 'rm -rf "$SMOKE_TMPDIR"' EXIT

# The systemd EnvironmentFile is data, not shell code. Import only the token
# needed here; CLI probes receive the chosen file explicitly. Keep test-control
# flags in the invoking environment rather than importing arbitrary file keys.
legacy_token="${EASY_WAF_ADMIN_TOKEN:-}"
if grep -q '^EASY_WAF_ADMIN_TOKEN=' "$ENV_FILE"; then
  legacy_token="$(easy_waf_read_env_value "$ENV_FILE" EASY_WAF_ADMIN_TOKEN)"
elif [[ "$?" != 1 ]]; then
  echo "ERROR: cannot read env file" >&2
  exit 1
fi
api_token="$legacy_token"
session_jwt=""
step_up_jwt=""

CURL_TLS=()
if [[ "$BASE" == https://* ]]; then
  if [[ "${EASY_WAF_CURL_INSECURE:-0}" == "1" ]]; then
    CURL_TLS=(--insecure)
  elif [[ -f "$API_CA_CERT" ]]; then
    CURL_TLS=(--cacert "$API_CA_CERT")
  fi
fi

smoke_curl() {
  curl "${CURL_TLS[@]}" --connect-timeout 5 --max-time 30 -sS "$@" 2>/dev/null
}

# curl reads the bearer from a private file rather than its process arguments.
smoke_curl_auth() {
  local token="$1" header="$SMOKE_TMPDIR/authorization"
  shift
  [[ -n "$token" && "$token" != *[[:cntrl:]]* ]] || return 1
  printf 'Authorization: Bearer %s\n' "$token" >"$header" || return 1
  smoke_curl -H "@$header" "$@"
}

# api <method> <path> [data] — prints "<status>\n<body>".
# curl can print an HTTP status even when the response transfer failed.
api() {
  local method="$1" path="$2" data="${3:-}"
  local args=(-o "${SMOKE_TMPDIR}/body" -w '%{http_code}'
    -X "$method" "${BASE}${path}"
    -H "X-Requested-With: XMLHttpRequest")
  if [[ -n "$data" ]]; then
    args+=(-H "Content-Type: application/json" -d "$data")
  fi
  local code
  if ! code="$(smoke_curl_auth "$api_token" "${args[@]}")"; then
    printf '000\n'
    return
  fi
  printf '%s\n' "$code"
  cat "${SMOKE_TMPDIR}/body" 2>/dev/null
}

operator_login() {
  local login_json login_code confirm_json confirm_code
  login_json="$(printf '{\"username\":\"%s\",\"password\":\"%s\"' \
    "$(json_escape "${EASY_WAF_SMOKE_USER}")" \
    "$(json_escape "${EASY_WAF_SMOKE_PASSWORD}")")"
  if [[ -n "${EASY_WAF_SMOKE_TOTP_CODE:-}" ]]; then
    login_json+=",\"totp_code\":\"$(json_escape "${EASY_WAF_SMOKE_TOTP_CODE}")\""
  fi
  login_json+='}'

  if ! login_code="$(smoke_curl -o "${SMOKE_TMPDIR}/login" -w '%{http_code}' \
    -X POST "${BASE}/api/v1/auth/login" \
    -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
    --data-binary @- <<<"$login_json")"; then
    fail "operator login request failed"
    return 1
  fi
  if [[ "$login_code" != "200" ]]; then
    fail "operator login -> $login_code: $(head -c 200 "${SMOKE_TMPDIR}/login")"
    return 1
  fi
  session_jwt="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "${SMOKE_TMPDIR}/login")"
  if [[ -z "$session_jwt" ]]; then
    fail "operator login returned no token"
    return 1
  fi
  api_token="$session_jwt"
  pass "operator session established"

  confirm_json="$(printf '{\"password\":\"%s\"}' "$(json_escape "${EASY_WAF_SMOKE_PASSWORD}")")"
  if ! confirm_code="$(smoke_curl_auth "$session_jwt" -o "${SMOKE_TMPDIR}/confirm" -w '%{http_code}' \
    -X POST "${BASE}/api/v1/auth/confirm" \
    -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
    --data-binary @- <<<"$confirm_json")"; then
    fail "password confirmation request failed"
    return 1
  fi
  if [[ "$confirm_code" != "200" ]]; then
    fail "password confirmation -> $confirm_code: $(head -c 200 "${SMOKE_TMPDIR}/confirm")"
    return 1
  fi
  step_up_jwt="$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' "${SMOKE_TMPDIR}/confirm")"
  if [[ -z "$step_up_jwt" ]]; then
    fail "password confirmation returned no token"
    return 1
  fi
  pass "operator session passed password confirmation"
}

status_of() { head -1 <<<"$1"; }
body_of() { tail -n +2 <<<"$1"; }

unit_installed() { systemctl list-unit-files "${1}.service" &>/dev/null; }

# unit_state prints the unit state, or "" when systemd is not running (container,
# chroot) — a missing answer means "cannot tell", not "broken".
unit_state() { systemctl is-active "${1}.service" 2>/dev/null; }

check_running_binary() {
  local unit="$1" installed="$2" pid running
  if ! pid="$(systemctl show -p MainPID --value "$unit.service" 2>/dev/null)" || [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
    fail "$unit is active but its main PID could not be verified"
    return
  fi
  running="/proc/$pid/exe"
  if [[ "$running" -ef "$installed" ]] || cmp -s -- "$running" "$installed"; then
    pass "$unit is running the installed binary"
  else
    fail "$unit running binary does not match $installed"
  fi
}

check_expected_version() {
  local name="$1" installed="$2" output
  [[ -n "$EXPECTED_VERSION" ]] || return 0
  if [[ ! -x "$installed" ]] || ! output="$("$installed" --version 2>/dev/null)"; then
    fail "could not read $name version from $installed"
  elif [[ "$output" != "$name $EXPECTED_VERSION" ]]; then
    fail "$name does not report expected version $EXPECTED_VERSION"
  else
    pass "$name reports expected version $EXPECTED_VERSION"
  fi
}

check_mcp_listener() {
  local unit=easy-waf-mcpd.service properties key value load='' enabled='' active='' pid=''
  local sockets endpoint owners seen=0
  if ! properties="$(systemctl show -p LoadState -p UnitFileState -p ActiveState -p MainPID "$unit" 2>/dev/null)" &&
    [[ "$properties" != *LoadState=not-found* ]]; then
    skip "$unit status unavailable"
    return
  fi
  while IFS='=' read -r key value; do
    case "$key" in
      LoadState) load="$value" ;;
      UnitFileState) enabled="$value" ;;
      ActiveState) active="$value" ;;
      MainPID) pid="$value" ;;
    esac
  done <<<"$properties"
  if ! sockets="$(ss -H -ltnp 2>/dev/null)"; then
    fail "$unit TCP listeners could not be verified"
    return
  fi
  if [[ "$active" != active ]]; then
    if [[ "$sockets" == *'("easy-waf-mcpd",pid='* ]]; then
      fail "$unit is not active but an MCP process is listening"
    elif [[ "$load" == not-found ]]; then
      skip "$unit not installed"
    elif [[ "$active" == inactive && ( "$enabled" == disabled || "$enabled" == masked || "$enabled" == masked-runtime ) ]]; then
      pass "$unit is $enabled with no TCP listener"
    else
      fail "$unit unexpected state (active: ${active:-unknown}, unit file: ${enabled:-unknown})"
    fi
    return
  fi
  if [[ "$load" != loaded || ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
    fail "$unit is active but its main PID could not be verified"
    return
  fi
  while read -r _ _ _ endpoint _ owners; do
    if [[ "$owners" != *"pid=$pid,"* && "$owners" != *'("easy-waf-mcpd",pid='* ]]; then
      continue
    fi
    if [[ "$owners" != *"pid=$pid,"* ]]; then
      fail "$unit has a listener outside the managed process"
      return
    fi
    case "$endpoint" in
      127.*:* | "[::1]":* | "[::ffff:127."*"]":*) seen=$((seen + 1)) ;;
      *) fail "$unit has a non-loopback TCP listener"; return ;;
    esac
  done <<<"$sockets"
  if ((seen == 1)); then
    pass "$unit has one loopback TCP listener"
    check_expected_version easy-waf-mcpd /usr/sbin/easy-waf-mcpd
    check_running_binary easy-waf-mcpd /usr/sbin/easy-waf-mcpd
  else
    fail "$unit did not expose exactly one loopback TCP listener"
  fi
}

check_backup_timer() {
  local timer=easy-waf-backup.timer properties key value load='' enabled='' active='' sub='' next=''
  if ! properties="$(systemctl show -p LoadState -p UnitFileState -p ActiveState -p SubState \
    -p NextElapseUSecRealtime -p NextElapseUSecMonotonic "$timer" 2>/dev/null)"; then
    skip "$timer status unavailable"
    return
  fi
  while IFS='=' read -r key value; do
    case "$key" in
      LoadState) load="$value" ;;
      UnitFileState) enabled="$value" ;;
      ActiveState) active="$value" ;;
      SubState) sub="$value" ;;
      NextElapseUSecRealtime|NextElapseUSecMonotonic)
        case "$value" in
          '' | n/a | 0 | infinity) ;;
          *) next="$value" ;;
        esac
        ;;
    esac
  done <<<"$properties"
  if [[ "$enabled" == disabled || "$enabled" == masked || "$enabled" == masked-runtime ]]; then
    skip "$timer is $enabled"
  elif [[ "$load" == not-found ]]; then
    skip "$timer not installed"
  elif [[ "$load" != loaded || ( "$enabled" != enabled && "$enabled" != enabled-runtime ) ]]; then
    fail "$timer is not a loaded, enabled timer (load: ${load:-unknown}, unit file: ${enabled:-unknown})"
  elif [[ "$active" != active ]]; then
    fail "$timer is $enabled but ${active:-has unknown status}"
  elif [[ "$sub" == running ]]; then
    pass "$timer active (backup running)"
  elif [[ -z "$next" ]]; then
    fail "$timer is active but has no next run"
  else
    pass "$timer active with a scheduled run"
  fi
}

section "secrets"
env_mode="$(stat -c '%a %U:%G' "$ENV_FILE" 2>/dev/null || echo unknown)"
if [[ "$env_mode" == "600 root:root" ]]; then
  pass "$ENV_FILE is root-only"
else
  fail "$ENV_FILE is $env_mode, want 600 root:root (group easy-waf includes haproxy)"
fi

section "systemd units"
for unit in easy-waf-hostd easy-waf-api easy-waf-acmed; do
  check_expected_version "$unit" "/usr/sbin/$unit"
  if ! unit_installed "$unit"; then
    if [[ -n "$EXPECTED_VERSION" ]]; then
      fail "$unit not installed"
    else
      skip "$unit not installed"
    fi
    continue
  fi
  state="$(unit_state "$unit")"
  case "$state" in
    active) pass "$unit active"; check_running_binary "$unit" "/usr/sbin/$unit" ;;
    "" | unknown)
      if [[ -n "$EXPECTED_VERSION" ]]; then
        fail "$unit state could not be verified"
      else
        skip "$unit state unknown (systemd not running?)"
      fi
      ;;
    *) fail "$unit is $state" ;;
  esac
done
check_expected_version easy-waf-admin "$ADMIN_BIN"
check_mcp_listener
if [[ -n "$EXPECTED_VERSION" ]] && ((fail_n)); then
  echo "ERROR: appliance did not pass verification for expected release $EXPECTED_VERSION" >&2
  exit 1
fi
check_backup_timer

# 1.2.1 shipped ProtectHome=false for the broker; with true, /home is invisible
# to it and SSH key management silently cannot write.
if ! unit_installed easy-waf-hostd; then
  skip "easy-waf-hostd not installed — ProtectHome not checked"
elif systemctl show easy-waf-hostd.service -p ProtectHome 2>/dev/null | grep -q 'ProtectHome=no'; then
  pass "easy-waf-hostd ProtectHome disabled (SSH key management can write)"
else
  fail "easy-waf-hostd still runs with ProtectHome enabled — reload units: systemctl daemon-reload"
fi

section "appliance diagnostics (easy-waf-admin doctor)"
if [[ -x "$ADMIN_BIN" ]]; then
  if "$ADMIN_BIN" doctor -env-file "$ENV_FILE" -state-dir "$STATE" >"${SMOKE_TMPDIR}/doctor" 2>&1; then
    pass "doctor reported no failures"
  else
    fail "doctor reported problems:"
    sed 's/^/        /' "${SMOKE_TMPDIR}/doctor" >&2
  fi
else
  skip "$ADMIN_BIN not found"
fi

section "management API"
health="$(smoke_curl -o /dev/null -w '%{http_code}' "${BASE}/health")" || health=000
if [[ "$health" == "200" ]]; then
  pass "GET /health -> 200"
else
  fail "GET /health -> ${health:-no answer}"
fi
ready="$(smoke_curl -o /dev/null -w '%{http_code}' "${BASE}/health/ready")" || ready=000
if [[ "$ready" == "200" ]]; then
  pass "GET /health/ready -> 200"
else
  fail "GET /health/ready -> ${ready:-no answer}"
fi

# 1.2.1 ignores a legacy token shorter than 24 characters; automation using one
# stops working, and the symptom is a plain 401.
if [[ -z "$legacy_token" ]]; then
  skip "EASY_WAF_ADMIN_TOKEN not set (operator session can cover authenticated reads)"
elif ((${#legacy_token} < 24)); then
  fail "EASY_WAF_ADMIN_TOKEN is ${#legacy_token} chars; 1.2.1 ignores anything under 24 — rotate it"
else
  pass "EASY_WAF_ADMIN_TOKEN length ok (${#legacy_token})"
fi

if [[ -n "${EASY_WAF_SMOKE_USER:-}" || -n "${EASY_WAF_SMOKE_PASSWORD:-}" ]]; then
  if [[ -z "${EASY_WAF_SMOKE_USER:-}" || -z "${EASY_WAF_SMOKE_PASSWORD:-}" ]]; then
    fail "set both EASY_WAF_SMOKE_USER and EASY_WAF_SMOKE_PASSWORD"
  else
    operator_login || true
  fi
fi

if [[ -n "$api_token" ]]; then
  r="$(api GET /api/v1/status)"
  if [[ "$(status_of "$r")" == "200" ]]; then
    pass "GET /api/v1/status -> 200 (database reachable, migrations applied)"
  else
    fail "GET /api/v1/status -> $(status_of "$r"): $(body_of "$r" | head -c 200)"
  fi

  r="$(api GET /api/v1/applications)"
  if [[ "$(status_of "$r")" == "200" ]]; then
    pass "GET /api/v1/applications -> 200"
  else
    fail "GET /api/v1/applications -> $(status_of "$r")"
  fi
else
  skip "authenticated API reads need EASY_WAF_ADMIN_TOKEN or operator credentials"
fi

section "HAProxy config and reload"
if [[ "${EASY_WAF_SMOKE_SKIP_APPLY:-0}" == "1" ]]; then
  skip "apply skipped by EASY_WAF_SMOKE_SKIP_APPLY=1"
elif [[ ! -x "$ADMIN_BIN" ]]; then
  fail "$ADMIN_BIN not found — cannot exercise edge apply"
else
  if "$ADMIN_BIN" apply-edge \
    -env-file "$ENV_FILE" \
    -state-dir "$STATE" \
    -label smoke-appliance >"${SMOKE_TMPDIR}/apply-edge" 2>&1; then
    pass "easy-waf-admin apply-edge"
  else
    # 1.2.1 validates application fields at render time and fails closed, naming
    # the offending application; a row stored before those validators trips here.
    fail "easy-waf-admin apply-edge failed:"
    sed 's/^/        /' "${SMOKE_TMPDIR}/apply-edge" >&2
  fi
fi

CFG="${STATE}/haproxy/haproxy.cfg"
if [[ -f "$CFG" ]] && command -v haproxy &>/dev/null; then
  if haproxy -c -f "$CFG" >"${SMOKE_TMPDIR}/haproxy" 2>&1; then
    pass "haproxy -c on the live config"
  else
    fail "haproxy -c failed:"
    sed 's/^/        /' "${SMOKE_TMPDIR}/haproxy" >&2
  fi
else
  skip "live config or haproxy binary not found"
fi

# The install keeps running with a root master when the preflight in
# fix-haproxy-easy-waf-dropin.sh fails, so a working edge proves nothing here.
haproxy_master_user="$(ps -o user= -p "$(systemctl show -p MainPID --value haproxy.service 2>/dev/null)" 2>/dev/null)"
case "$haproxy_master_user" in
  haproxy) pass "haproxy master runs as haproxy" ;;
  "") skip "haproxy master not found" ;;
  *) fail "haproxy master runs as $haproxy_master_user — see the warning from scripts/fix-haproxy-easy-waf-dropin.sh" ;;
esac

if unit_installed haproxy; then
  state="$(unit_state haproxy)"
  case "$state" in
    active) pass "haproxy active after apply" ;;
    "" | unknown) skip "haproxy state unknown (systemd not running?)" ;;
    *) fail "haproxy is $state after apply — a reload may have failed" ;;
  esac
fi

if [[ -n "$api_token" ]]; then
  stats_ok=0
  for ((attempt=0; attempt<6; attempt++)); do
    r="$(api GET /api/v1/stats/haproxy)"
    # HTTP 200 can still contain a collector error. Allow the five-second
    # stats cache to expire after reload before declaring runtime failure.
    if [[ "$(status_of "$r")" == 200 ]] &&
      grep -qE '"frontends"[[:space:]]*:[[:space:]]*\[' <<<"$(body_of "$r")" &&
      ! grep -qE '"error"[[:space:]]*:[[:space:]]*"[^"]' <<<"$(body_of "$r")"; then
      stats_ok=1
      break
    fi
    if ((attempt < 5)); then sleep 1; fi
  done
  if [[ "$stats_ok" == 1 ]]; then
    pass "HAProxy runtime stats available after reload"
  else
    fail "HAProxy runtime stats unavailable after reload"
  fi
else
  skip "HAProxy runtime stats need an authenticated session"
fi

# 1.3.0 keeps '-' in generated identifiers, so backend names change for hosts
# containing a dash. Dashboards keyed on the old names need updating.
if [[ -f "$CFG" ]] && grep -qE '^backend bk_[A-Za-z0-9_]*-' "$CFG"; then
  echo "  NOTE  generated backend names now keep '-' (e.g. $(grep -oE '^backend bk_\S+' "$CFG" | grep -- - | head -1 | awk '{print $2}')) — update metrics dashboards"
fi

section "GeoIP"
GEO_DIR="${STATE}/geoip"
if [[ -d "$GEO_DIR" ]]; then
  owner="$(stat -c '%U' "$GEO_DIR" 2>/dev/null || echo unknown)"
  if [[ "$owner" == "easy-waf" ]]; then
    pass "$GEO_DIR owned by easy-waf (UI upload can install)"
  else
    fail "$GEO_DIR owned by '$owner' — UI upload will fail: chown easy-waf:easy-waf $GEO_DIR"
  fi
else
  skip "$GEO_DIR does not exist yet"
fi

if [[ -n "${EASY_WAF_SMOKE_MMDB:-}" ]]; then
  if [[ ! -f "$EASY_WAF_SMOKE_MMDB" ]]; then
    fail "EASY_WAF_SMOKE_MMDB=$EASY_WAF_SMOKE_MMDB not found"
  elif [[ -z "$step_up_jwt" ]]; then
    skip "GeoIP upload needs EASY_WAF_SMOKE_USER/EASY_WAF_SMOKE_PASSWORD and a confirmed session"
  else
    if ! code="$(smoke_curl_auth "$step_up_jwt" --max-time 120 -o "${SMOKE_TMPDIR}/geoip" -w '%{http_code}' \
      -X POST "${BASE}/api/v1/geoip/database" \
      -H "X-Requested-With: XMLHttpRequest" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${EASY_WAF_SMOKE_MMDB}")"; then
      fail "GeoIP upload request failed"
    elif [[ "$code" == "200" ]]; then
      pass "GeoIP upload -> 200: $(tr -d '\n' <"${SMOKE_TMPDIR}/geoip" | head -c 200)"
    else
      fail "GeoIP upload -> $code: $(head -c 300 "${SMOKE_TMPDIR}/geoip")"
    fi
  fi
else
  skip "no EASY_WAF_SMOKE_MMDB — upload not exercised"
fi

if [[ -n "$api_token" ]]; then
  r="$(api GET '/api/v1/geoip/lookup?ip=8.8.8.8&nocache=1')"
  if [[ "$(status_of "$r")" == "200" ]]; then
    pass "GeoIP lookup 8.8.8.8 -> $(body_of "$r" | tr -d '\n' | head -c 120)"
  else
    fail "GeoIP lookup -> $(status_of "$r"); check the configured provider, database and upstream availability"
  fi
fi

section "session revocation (1.2.1)"
if [[ -n "${EASY_WAF_SMOKE_USER:-}" && -n "${EASY_WAF_SMOKE_PASSWORD:-}" ]]; then
  if [[ -z "$session_jwt" ]]; then
    skip "operator session was not established"
  else
    me() {
      smoke_curl_auth "$session_jwt" -o /dev/null -w '%{http_code}' "${BASE}/api/v1/auth/me" \
        -H 'X-Requested-With: XMLHttpRequest'
    }
    before="$(me)" || before=000
    logout="$(smoke_curl_auth "$session_jwt" -o /dev/null -w '%{http_code}' -X POST "${BASE}/api/v1/auth/logout" \
      -H 'X-Requested-With: XMLHttpRequest' \
      -H 'Content-Type: application/json' -d '{}')" || logout=000
    after="$(me)" || after=000
    if [[ "$before" == "200" && "$logout" == "200" && "$after" == "401" ]]; then
      pass "logout revokes the session server-side (200 -> 401)"
    else
      fail "logout verification failed: /auth/me $before -> /auth/logout $logout -> /auth/me $after"
    fi
  fi
else
  skip "set EASY_WAF_SMOKE_USER/EASY_WAF_SMOKE_PASSWORD to verify logout"
fi

section "summary"
echo "  passed: $pass_n   failed: $fail_n   skipped: $skip_n"
if ((fail_n > 0)); then
  echo "  smoke test FAILED" >&2
  exit 1
fi
echo "  smoke test OK"
