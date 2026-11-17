#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir -p "$ROOT/scripts/lib"
[[ "$(tail -n 1 "$SOURCE_DIR/install.sh")" == 'main "$@"' ]]
sed '$d' "$SOURCE_DIR/install.sh" >"$ROOT/scripts/install.sh"
cp "$SOURCE_DIR/lib/env-file.sh" "$ROOT/scripts/lib/"
# shellcheck source=/dev/null
source "$ROOT/scripts/install.sh"
# shellcheck source=lib/crowdsec-install.sh
source "$SOURCE_DIR/lib/crowdsec-install.sh"

# This test can run without root privileges.
easy_waf_secure_env_file() { :; }
sleep() { :; }
curl() {
  local header
  [[ "$1" == -q && " $* " == *' -H @- '* && " $* " == *' --noproxy * '* ]] || return 90
  IFS= read -r header || return 90
  printf '%s\n' "$header" >>"$ROOT/probes"
  case "$header" in
    'X-Api-Key: working-spoa'|'X-Api-Key: working-api'|'X-Api-Key: replacement-'*) printf '200' ;;
    'X-Api-Key: rejected') printf '403' ;;
    'X-Api-Key: unauthorized') printf '401' ;;
    'X-Api-Key: server-error') printf '503' ;;
    'X-Api-Key: offline') return 7 ;;
    *) return 90 ;;
  esac
}
cscli() {
  [[ "$1" == bouncers ]] || return 90
  printf '%s %s\n' "$2" "$3" >>"$ROOT/registrations"
  if [[ "$2" == add ]]; then
    printf 'replacement-%s\n' "$3"
  fi
}
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

env_file="$ROOT/easy-waf.env"
yaml="$ROOT/spoa.yaml"
prepare() {
  local spoa="$1" api="$2"
  local spoa_url="${3-http://127.0.0.1:8080/}" api_url="${4-http://127.0.0.1:8080}"
  printf '# keep this comment\nCROWDSEC_LAPI_URL=%s\nCROWDSEC_LAPI_KEY=%s\nUNRELATED=stay\n' "$api_url" "$api" >"$env_file"
  printf 'api_url: "%s" # package scalar\napi_key: "%s" # top-level key\nother:\n  api_key: nested\n' "$spoa_url" "$spoa" >"$yaml"
  cp "$env_file" "$ROOT/before.env"
  cp "$yaml" "$ROOT/before.yaml"
  : >"$ROOT/registrations"
  : >"$ROOT/probes"
}
unchanged() {
  cmp -s "$env_file" "$ROOT/before.env" &&
    cmp -s "$yaml" "$ROOT/before.yaml" &&
    [[ ! -s "$ROOT/registrations" ]]
}

prepare working-spoa working-api
easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"
unchanged || fail 'working credentials or files were changed'
[[ "$(wc -l <"$ROOT/probes")" -eq 2 ]] || fail 'both local credentials must be checked'

prepare rejected working-api
easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"
[[ "$(cat "$ROOT/registrations")" == $'delete easy-waf-spoa\nadd easy-waf-spoa' ]] || fail 'only SPOA should be replaced'
cmp -s "$env_file" "$ROOT/before.env" || fail 'API env was rewritten'
[[ "$(crowdsec_read_spoa_setting "$yaml" api_key)" == replacement-easy-waf-spoa ]] || fail 'SPOA replacement not saved'
grep -qx '  api_key: nested' "$yaml" || fail 'nested YAML changed'

prepare working-spoa unauthorized
easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"
[[ "$(cat "$ROOT/registrations")" == $'delete easy-waf-api\nadd easy-waf-api' ]] || fail 'only API should be replaced'
cmp -s "$yaml" "$ROOT/before.yaml" || fail 'SPOA settings were rewritten'
grep -qx 'CROWDSEC_LAPI_KEY=replacement-easy-waf-api' "$env_file" || fail 'API replacement not saved'
grep -qx 'UNRELATED=stay' "$env_file" || fail 'unrelated env entry changed'

# shellcheck disable=SC2016
prepare '${API_KEY}' '' http://127.0.0.1:8080/ ''
easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"
[[ "$(wc -l <"$ROOT/registrations")" -eq 4 ]] || fail 'fresh bootstrap needs both registrations'
grep -qx 'CROWDSEC_LAPI_URL=http://127.0.0.1:8080/' "$env_file" || fail 'default endpoint missing'

for unavailable in offline server-error; do
  prepare rejected "$unavailable"
  if easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"; then
    fail 'an unavailable LAPI was treated as successful'
  fi
  unchanged || fail 'a rejected key was modified before both probes completed'
done

prepare remote-spoa remote-api https://spoa.example.invalid https://api.example.invalid
easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"
unchanged || fail 'custom endpoint settings changed'
[[ ! -s "$ROOT/probes" ]] || fail 'a custom endpoint key was sent to the local probe'

prepare working-spoa working-api
printf 'api_key: duplicate\n' >>"$yaml"
cp "$yaml" "$ROOT/before.yaml"
if easy_waf_prepare_crowdsec_bouncers "$env_file" "$yaml"; then
  fail 'ambiguous SPOA configuration was accepted'
fi
unchanged || fail 'ambiguous configuration caused changes'
echo 'OK: CrowdSec installer key preservation and recovery'
