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
if [[ "${ROOT_ENV_TEST_SYNC_EXIT:-0}" != 0 ]]; then
  printf 'fixture-private-api-error\n' >&2
  exit "$ROOT_ENV_TEST_SYNC_EXIT"
fi
printf '%s\n' "$DATABASE_URL" "$CROWDSEC_LAPI_URL" "$CROWDSEC_LAPI_KEY" \
  "$CROWDSEC_LAPI_ALLOWED_ORIGINS" "$EASY_WAF_STATE_DIR" >"$ROOT_ENV_TEST_RESULT"
MOCK
chmod 0700 "$ROOT/bin/api"
function_source="$(sed -n '/^easy_waf_sync_settings_to_db() {$/,/^}$/p' "$SCRIPT_DIR/install.sh")"
[[ -n "$function_source" ]] || fail 'missing installer sync function'
eval "$function_source"
log() { printf '%s\n' "$*"; }
timeout() { [[ "$1 $2 $3" == '-k 5s 75s' ]] || fail 'sync lost timeout'; shift 3; "$@"; }
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
sync_status=0
ROOT_ENV_TEST_SYNC_EXIT=12 easy_waf_sync_settings_to_db >"$ROOT/db-failure-log" 2>&1 || sync_status=$?
[[ "$sync_status" == 12 ]] || fail 'installer did not propagate a database sync failure'
grep -Fq 'ERROR: PostgreSQL settings sync failed (exit 12)' "$ROOT/db-failure-log"
if grep -Fq 'fixture-private-api-error' "$ROOT/db-failure-log"; then
  fail 'installer exposed raw settings sync output'
fi
EASY_WAF_ENABLE_SYSTEMD_UNITS=0 ROOT_ENV_TEST_SYNC_EXIT=12 easy_waf_sync_settings_to_db >"$ROOT/staged-log" 2>&1 ||
  fail 'staged installer could not defer a failed sync'
grep -Fq 'settings sync deferred' "$ROOT/staged-log"
EASY_WAF_SKIP_SYSTEMD=1 ROOT_ENV_TEST_SYNC_EXIT=12 easy_waf_sync_settings_to_db >"$ROOT/skipped-log" 2>&1 ||
  fail 'installer that skips systemd could not defer a failed sync'
(
  : >"$CFG_DIR/easy-waf.env"
  rm "$ROOT_ENV_TEST_RESULT"
  if DATABASE_URL="$dsn" easy_waf_sync_settings_to_db >"$ROOT/missing-dsn-log" 2>&1; then
    fail 'installer used a process DSN missing from the appliance env'
  fi
  EASY_WAF_ENABLE_SYSTEMD_UNITS=0 easy_waf_sync_settings_to_db >"$ROOT/staged-no-dsn-log" 2>&1 ||
    fail 'staged installer rejected an unconfigured database'
  [[ ! -e "$ROOT_ENV_TEST_RESULT" ]] || fail 'unconfigured database remained accessible through ambient env'
)
printf 'DATABASE_URL="%s"\n' "$dsn" >"$CFG_DIR/easy-waf.env"
easy_waf_sync_settings_to_db >"$ROOT/restored-fixture-log" 2>&1
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
printf 'UNUSED=%s\nROOT_ENV_UNUSED_SECRET=fixture-only\nEASY_WAF_NFT_MGMT_LAN=1\nEASY_WAF_NFT_MGMT_PORTS="8080 9443"\nEASY_WAF_NFT_EDGE=0\nEASY_WAF_EXTRA_LAN_CIDR=198.51.100.0/24\nEASY_WAF_NFT_ZABBIX_AGENT=1\n' \
  "\$(touch \"$marker\")" >"$EASY_WAF_ENV_FILE"
export EASY_WAF_NFT_EDGE=1
unset EASY_WAF_NFT_ZABBIX_AGENT
bash "$ROOT/repair/fix-nftables-edge.sh" >"$ROOT/repair-log" 2>&1
[[ ! -e "$marker" ]] || fail 'repair executed env file'
printf '%s\n' 1 '8080 9443' 0 '198.51.100.0/24' 1 >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'repair lost selected firewall options'
EASY_WAF_NFT_ZABBIX_AGENT=0 bash "$ROOT/repair/fix-nftables-edge.sh" >"$ROOT/repair-log" 2>&1
printf '%s\n' 1 '8080 9443' 0 '198.51.100.0/24' 0 >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'repair ignored explicit Zabbix disable'
printf '\nEASY_WAF_NFT_ZABBIX_AGENT=0\n' >>"$EASY_WAF_ENV_FILE"
EASY_WAF_NFT_ZABBIX_AGENT=1 bash "$ROOT/repair/fix-nftables-edge.sh" >"$ROOT/repair-log" 2>&1
printf '%s\n' 1 '8080 9443' 0 '198.51.100.0/24' 1 >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'repair ignored explicit Zabbix enable'
printf 'EASY_WAF_FIREWALLD_MGMT_LAN=0\nEASY_WAF_FIREWALLD_MGMT_PORTS="9000 9443"\nEASY_WAF_FIREWALLD_EDGE=0\n' >"$EASY_WAF_ENV_FILE"
unset EASY_WAF_NFT_MGMT_LAN EASY_WAF_NFT_MGMT_PORTS EASY_WAF_NFT_EDGE EASY_WAF_EXTRA_LAN_CIDR EASY_WAF_NFT_ZABBIX_AGENT
bash "$ROOT/repair/fix-nftables-edge.sh" >"$ROOT/repair-log" 2>&1
printf '%s\n' 0 '9000 9443' 0 '' '' >"$ROOT/expected"
cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'repair lost legacy aliases'

# The source installer (also used by upgrade.sh) leaves the unset choice to
# the same privileged leaf as the repair script.
(
  function_source="$(sed -n '/^configure_nftables_appliance() {$/,/^}$/p' "$SCRIPT_DIR/install.sh")"
  [[ -n "$function_source" ]] || fail 'missing installer firewall function'
  eval "$function_source"
  SCRIPT_DIR="$ROOT/repair" EASY_WAF_INSTALL_OS_PACKAGES=1 configure_nftables_appliance
  printf '%s\n' 1 '8000 8443' 1 '' '' >"$ROOT/expected"
  cmp "$ROOT/expected" "$ROOT_ENV_TEST_RESULT" || fail 'installer forced a Zabbix default on upgrade'
)

# shellcheck source=lib/nftables-easy-waf.sh
source "$SCRIPT_DIR/lib/nftables-easy-waf.sh"
EASY_WAF_NFT_RULES="$ROOT/rendered.nft"
easy_waf_nft_write_ruleset
[[ "$(easy_waf_nft_read_zabbix)" == 0 ]] || fail 'clean install enabled Zabbix'

easy_waf_nft_write_ruleset 1 '8080 9443' 0 '198.51.100.0/24' 1
grep -F '198.51.100.0/24 } tcp dport { 8080, 9443 } accept' "$EASY_WAF_NFT_RULES" >/dev/null ||
  fail 'extra management CIDR was lost'
grep -Fx '    ip saddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport 10050 accept' "$EASY_WAF_NFT_RULES" >/dev/null ||
  fail 'Zabbix rule must use the default LAN ranges'
easy_waf_nft_write_ruleset
[[ "$(easy_waf_nft_read_zabbix)" == 1 ]] || fail 'upgrade discarded the existing Zabbix rule'

printf '%s\n' '    # easy-waf:zabbix-agent' \
  '    ip saddr { 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16' \
  ', 198.51.100.0/24 } tcp dport 10050 accept' >"$EASY_WAF_NFT_RULES"
easy_waf_nft_write_ruleset
[[ "$(easy_waf_nft_read_zabbix)" == 1 ]] || fail 'upgrade discarded a legacy multiline Zabbix rule'
if grep -qF '198.51.100.0/24' "$EASY_WAF_NFT_RULES"; then
  fail 'upgrade kept a legacy extra range in the Zabbix rule'
fi

cp "$EASY_WAF_NFT_RULES" "$ROOT/before-invalid.nft"
if easy_waf_nft_write_ruleset 1 '8080 9443' 0 '' invalid >"$ROOT/invalid-zabbix.log" 2>&1; then
  fail 'invalid Zabbix toggle was accepted'
fi
cmp "$ROOT/before-invalid.nft" "$EASY_WAF_NFT_RULES" || fail 'invalid toggle changed the ruleset'

easy_waf_nft_write_ruleset 1 '8080 9443' 0 '198.51.100.0/24' 0
if grep -qF 'tcp dport 10050' "$EASY_WAF_NFT_RULES"; then
  fail 'Zabbix rule was emitted with the switch off'
fi

# A marker without its associated allow rule must never grant access.
printf '%s\n' '    # easy-waf:zabbix-agent' '    tcp dport 22 accept' >"$EASY_WAF_NFT_RULES"
easy_waf_nft_write_ruleset
[[ "$(easy_waf_nft_read_zabbix)" == 0 ]] || fail 'an orphaned marker enabled Zabbix'
echo 'OK: root env inputs stay data'
