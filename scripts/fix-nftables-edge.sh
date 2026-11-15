#!/usr/bin/env bash
# Re-apply Easy WAF nftables ruleset (edge 80/443 + management ports). Run as root.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/nftables-easy-waf.sh
source "${SCRIPT_DIR}/lib/nftables-easy-waf.sh"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh"
[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
ENV_FILE="${EASY_WAF_ENV_FILE:-/etc/easy-waf/easy-waf.env}"
if [[ -f "$ENV_FILE" ]]; then
  easy_waf_export_env_keys "$ENV_FILE" EASY_WAF_NFT_MGMT_LAN \
    EASY_WAF_NFT_MGMT_PORTS EASY_WAF_NFT_EDGE EASY_WAF_EXTRA_LAN_CIDR \
    EASY_WAF_FIREWALLD_MGMT_LAN EASY_WAF_FIREWALLD_MGMT_PORTS EASY_WAF_FIREWALLD_EDGE || {
    echo "cannot read firewall environment" >&2
    exit 1
  }
fi
easy_waf_nft_configure_appliance \
  "${EASY_WAF_NFT_MGMT_LAN:-${EASY_WAF_FIREWALLD_MGMT_LAN:-1}}" \
  "${EASY_WAF_NFT_MGMT_PORTS:-${EASY_WAF_FIREWALLD_MGMT_PORTS:-8000 8443}}" \
  "${EASY_WAF_NFT_EDGE:-${EASY_WAF_FIREWALLD_EDGE:-1}}" \
  "${EASY_WAF_EXTRA_LAN_CIDR:-}"
echo "nftables edge/management rules applied."
