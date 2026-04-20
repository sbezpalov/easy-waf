#!/usr/bin/env bash
# Open HAProxy edge ports in firewalld (services http + https → 80/tcp, 443/tcp).
# For hosts already installed before edge automation, or after firewalld was off during install.
# Env: EASY_WAF_FIREWALLD_ZONE (default public), EASY_WAF_FIREWALLD_EDGE_SERVICES (default "http https").
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || {
  echo "run as root: sudo bash $0" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/firewalld-management-api.sh
source "${SCRIPT_DIR}/lib/firewalld-management-api.sh"

systemctl start firewalld 2>/dev/null || true
easy_waf_firewalld_allow_edge_http_https \
  "${EASY_WAF_FIREWALLD_ZONE:-public}" \
  "${EASY_WAF_FIREWALLD_EDGE_SERVICES:-http https}"
