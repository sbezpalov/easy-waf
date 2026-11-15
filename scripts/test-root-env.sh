#!/usr/bin/env bash
# Real installer sync and repair entrypoint, private fake API/firewall operations.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/env-file.sh
source "$SCRIPT_DIR/lib/env-file.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$ROOT/config" "$ROOT/bin" "$ROOT/repair/lib"
export ROOT_ENV_TEST_RESULT="$ROOT/result"
cat >"$ROOT/bin/api" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == -sync-settings-only ]] || exit 90
[[ -z "${ROOT_ENV_UNUSED_SECRET+x}" ]] || exit 91
printf '%s\n' "$DATABASE_URL" "$CROWDSEC_LAPI_URL" "$CROWDSEC_LAPI_KEY" \
  "$CROWDSEC_LAPI_ALLOWED_ORIGINS" "$EASY_WAF_STATE_DIR" >"$ROOT_ENV_TEST_RESULT"
MOCK
chmod 0700 "$ROOT/bin/api"
function_source="$(sed -n '/^easy_waf_sync_settings_to_db() {$/,/^}$/p' "$SCRIPT_DIR/install.sh")"
[[ -n "$function_source" ]] || fail 'missing installer sync function'
eval "$function_source"
log() { :; }
timeout() { [[ "$1" == 25 ]] || fail 'sync lost timeout'; shift; "$@"; }
API_BIN="$ROOT/bin/api"
DIST_DIR="$ROOT/missing-dist"
export API_BIN DIST_DIR # Consumed by the actual function loaded above.
export not_expanded='must-stay-literal'
CFG_DIR="$ROOT/config"
STATE_DIR="$ROOT/state"
original_state="$STATE_DIR"
marker="$ROOT/executed"
dsn="postgres://fixture:literal-\$not_expanded@fixture.invalid/db"
key="literal-key-\$not_expanded;still-data"
printf 'UNUSED=%s\nROOT_ENV_UNUSED_SECRET=fixture-only\nDATABASE_URL="%s"\nCROWDSEC_LAPI_URL=http://127.0.0.1:8080\nCROWDSEC_LAPI_KEY=%s\nCROWDSEC_LAPI_ALLOWED_ORIGINS=https://fixture.invalid:8443\nSTATE_DIR=/incorrect-state\n' \
  "\$(touch \"$marker\")" "$dsn" "$key" >"$CFG_DIR/easy-waf.env"
unset DATABASE_URL CROWDSEC_LAPI_URL CROWDSEC_LAPI_KEY CROWDSEC_LAPI_ALLOWED_ORIGINS ROOT_ENV_UNUSED_SECRET
sync_status=0
easy_waf_sync_settings_to_db >"$ROOT/sync-log" 2>&1 || sync_status=$?
[[ ! -e "$marker" ]] || fail 'installer executed env file'
[[ "$sync_status" == 0 && -f "$ROOT_ENV_TEST_RESULT" ]] || fail 'sync did not reach API'
printf '%s\n' "$dsn" 'http://127.0.0.1:8080' "$key" 'https://fixture.invalid:8443' "$original_state" >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'sync changed literal values or selected state'
[[ "$STATE_DIR" == "$original_state" && -z "${DATABASE_URL+x}${CROWDSEC_LAPI_KEY+x}" ]] || fail 'sync changed installer environment'
(
  rm "$ROOT_ENV_TEST_RESULT"
  # Called by the real sync function loaded through eval above.
  # 0.9 flags the body; newer ShellCheck flags the definition.
  # shellcheck disable=SC2317,SC2329
  easy_waf_export_env_keys() { return 1; }
  if easy_waf_sync_settings_to_db >"$ROOT/read-failure-log" 2>&1; then
    fail 'sync accepted failed env read'
  fi
  [[ ! -e "$ROOT_ENV_TEST_RESULT" ]] || fail 'sync invoked API after failed env read'
)

# Stage the real repair entrypoint, replacing only its privileged leaf library.
cp "$SCRIPT_DIR/fix-nftables-edge.sh" "$ROOT/repair/"
cp "$SCRIPT_DIR/lib/env-file.sh" "$ROOT/repair/lib/"
cat >"$ROOT/repair/lib/nftables-easy-waf.sh" <<'MOCK'
easy_waf_nft_configure_appliance() {
  [[ -z "${ROOT_ENV_UNUSED_SECRET+x}" ]] || return 91
  printf '%s\n' "$@" >"$ROOT_ENV_TEST_RESULT"
}
MOCK
printf '#!/bin/sh\nprintf "0\\n"\n' >"$ROOT/bin/id"
chmod 0700 "$ROOT/bin/id"
export PATH="$ROOT/bin:$PATH"
export EASY_WAF_ENV_FILE="$ROOT/firewall.env"
printf 'UNUSED=%s\nROOT_ENV_UNUSED_SECRET=fixture-only\nEASY_WAF_NFT_MGMT_LAN=1\nEASY_WAF_NFT_MGMT_PORTS="8080 9443"\nEASY_WAF_NFT_EDGE=0\nEASY_WAF_EXTRA_LAN_CIDR=198.51.100.0/24\n' \
  "\$(touch \"$marker\")" >"$EASY_WAF_ENV_FILE"
export EASY_WAF_NFT_EDGE=1
bash "$ROOT/repair/fix-nftables-edge.sh" >"$ROOT/repair-log" 2>&1
[[ ! -e "$marker" ]] || fail 'repair executed env file'
printf '%s\n' 1 '8080 9443' 0 '198.51.100.0/24' >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'repair lost selected firewall options'
printf 'EASY_WAF_FIREWALLD_MGMT_LAN=0\nEASY_WAF_FIREWALLD_MGMT_PORTS="9000 9443"\nEASY_WAF_FIREWALLD_EDGE=0\n' >"$EASY_WAF_ENV_FILE"
unset EASY_WAF_NFT_MGMT_LAN EASY_WAF_NFT_MGMT_PORTS EASY_WAF_NFT_EDGE EASY_WAF_EXTRA_LAN_CIDR
bash "$ROOT/repair/fix-nftables-edge.sh" >"$ROOT/repair-log" 2>&1
printf '%s\n' 0 '9000 9443' 0 '' >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'repair lost legacy aliases'
echo 'OK: root env inputs stay data'
