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
#   sudo EASY_WAF_SMOKE_USER=admin EASY_WAF_SMOKE_PASSWORD=… bash scripts/smoke-appliance.sh
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

set -uo pipefail

STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
ENV_FILE="${EASY_WAF_ENV_FILE:-/etc/easy-waf/easy-waf.env}"
API_BASE="${EASY_WAF_API_BASE:-https://127.0.0.1:8443}"
BASE="${API_BASE%/}"
API_CA_CERT="${EASY_WAF_API_CA_CERT:-${STATE}/secrets/management.crt}"
ADMIN_BIN="${EASY_WAF_ADMIN_BIN:-/usr/sbin/easy-waf-admin}"

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

SMOKE_TMPDIR="$(mktemp -d)"
trap 'rm -rf "$SMOKE_TMPDIR"' EXIT

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

legacy_token="${EASY_WAF_ADMIN_TOKEN:-}"
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

# api <method> <path> [data] — prints "<status>\n<body>".
api() {
  local method="$1" path="$2" data="${3:-}"
  local args=("${CURL_TLS[@]}" -sS -o "${SMOKE_TMPDIR}/body" -w '%{http_code}'
    -X "$method" "${BASE}${path}"
    -H "Authorization: Bearer ${api_token}"
    -H "X-Requested-With: XMLHttpRequest")
  if [[ -n "$data" ]]; then
    args+=(-H "Content-Type: application/json" -d "$data")
  fi
  local code
  code="$(curl "${args[@]}" 2>/dev/null)"
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

  if ! login_code="$(curl "${CURL_TLS[@]}" -sS -o "${SMOKE_TMPDIR}/login" -w '%{http_code}' \
    -X POST "${BASE}/api/v1/auth/login" \
    -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
    --data-binary @- <<<"$login_json" 2>/dev/null)"; then
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
  if ! confirm_code="$(curl "${CURL_TLS[@]}" -sS -o "${SMOKE_TMPDIR}/confirm" -w '%{http_code}' \
    -X POST "${BASE}/api/v1/auth/confirm" \
    -H "Authorization: Bearer ${session_jwt}" \
    -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
    --data-binary @- <<<"$confirm_json" 2>/dev/null)"; then
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

section "secrets"
env_mode="$(stat -c '%a %U:%G' "$ENV_FILE" 2>/dev/null || echo unknown)"
if [[ "$env_mode" == "600 root:root" ]]; then
  pass "$ENV_FILE is root-only"
else
  fail "$ENV_FILE is $env_mode, want 600 root:root (group easy-waf includes haproxy)"
fi

section "systemd units"
for unit in easy-waf-hostd easy-waf-api easy-waf-acmed; do
  if ! unit_installed "$unit"; then
    skip "$unit not installed"
    continue
  fi
  state="$(unit_state "$unit")"
  case "$state" in
    active) pass "$unit active" ;;
    "" | unknown) skip "$unit state unknown (systemd not running?)" ;;
    *) fail "$unit is $state" ;;
  esac
done

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
  if "$ADMIN_BIN" doctor >"${SMOKE_TMPDIR}/doctor" 2>&1; then
    pass "doctor reported no failures"
  else
    fail "doctor reported problems:"
    sed 's/^/        /' "${SMOKE_TMPDIR}/doctor" >&2
  fi
else
  skip "$ADMIN_BIN not found"
fi

section "management API"
health="$(curl "${CURL_TLS[@]}" -sS -o /dev/null -w '%{http_code}' "${BASE}/health" 2>/dev/null)"
if [[ "$health" == "200" ]]; then
  pass "GET /health -> 200"
else
  fail "GET /health -> ${health:-no answer}"
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
    code="$(curl "${CURL_TLS[@]}" -sS -o "${SMOKE_TMPDIR}/geoip" -w '%{http_code}' \
      -X POST "${BASE}/api/v1/geoip/database" \
      -H "Authorization: Bearer ${step_up_jwt}" \
      -H "X-Requested-With: XMLHttpRequest" \
      -H "Content-Type: application/octet-stream" \
      --data-binary "@${EASY_WAF_SMOKE_MMDB}" 2>/dev/null)"
    if [[ "$code" == "200" ]]; then
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
    skip "GeoIP lookup -> $(status_of "$r") (provider may be disabled)"
  fi
fi

section "session revocation (1.2.1)"
if [[ -n "${EASY_WAF_SMOKE_USER:-}" && -n "${EASY_WAF_SMOKE_PASSWORD:-}" ]]; then
  if [[ -z "$session_jwt" ]]; then
    skip "operator session was not established"
  else
    me() {
      curl "${CURL_TLS[@]}" -sS -o /dev/null -w '%{http_code}' "${BASE}/api/v1/auth/me" \
        -H "Authorization: Bearer ${session_jwt}" -H 'X-Requested-With: XMLHttpRequest' 2>/dev/null
    }
    before="$(me)"
    curl "${CURL_TLS[@]}" -sS -o /dev/null -X POST "${BASE}/api/v1/auth/logout" \
      -H "Authorization: Bearer ${session_jwt}" -H 'X-Requested-With: XMLHttpRequest' \
      -H 'Content-Type: application/json' -d '{}' 2>/dev/null
    after="$(me)"
    if [[ "$before" == "200" && "$after" == "401" ]]; then
      pass "logout revokes the session server-side (200 -> 401)"
    else
      fail "logout did not revoke: /auth/me was $before, after logout $after"
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
