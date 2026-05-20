#!/usr/bin/env bash
# Re-apply Easy WAF nftables ruleset (edge 80/443 + management ports). Run as root.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/nftables-easy-waf.sh
source "${SCRIPT_DIR}/lib/nftables-easy-waf.sh"
[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 1; }
CFG_DIR="/etc/easy-waf"
if [[ -f "${CFG_DIR}/easy-waf.env" ]]; then
  # shellcheck source=/dev/null
  source "${CFG_DIR}/easy-waf.env" 2>/dev/null || true
fi
easy_waf_nft_configure_appliance \
  "${EASY_WAF_NFT_MGMT_LAN:-${EASY_WAF_FIREWALLD_MGMT_LAN:-1}}" \
  "${EASY_WAF_NFT_MGMT_PORTS:-${EASY_WAF_FIREWALLD_MGMT_PORTS:-8000 8443}}" \
  "${EASY_WAF_NFT_EDGE:-${EASY_WAF_FIREWALLD_EDGE:-1}}" \
  "${EASY_WAF_EXTRA_LAN_CIDR:-}"
echo "nftables edge/management rules applied."
