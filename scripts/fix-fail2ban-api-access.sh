#!/usr/bin/env bash
# LEGACY — pre-hostd repair (fail2ban group + socket drop-ins). Current installs use easy-waf-hostd.
# Grant easy-waf-api Fail2ban socket access (group + systemd drop-ins). Idempotent. Run as root.
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || {
  echo "Run as root: sudo bash $0" >&2
  exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${EASY_WAF_REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

# shellcheck source=lib/fail2ban-access.sh
source "${SCRIPT_DIR}/lib/fail2ban-access.sh"

easy_waf_install_fail2ban_api_access "$REPO_ROOT"
systemctl daemon-reload
systemctl restart fail2ban.service 2>/dev/null || true
easy_waf_fail2ban_fix_socket_permissions
systemctl restart easy-waf-api.service 2>/dev/null || true

if sudo -u easy-waf fail2ban-client ping 2>/dev/null | grep -qi pong; then
  easy_waf_fail2ban_log "fail2ban-client ping OK as easy-waf"
  exit 0
fi

echo "[easy-waf] ERROR: fail2ban-client ping failed for user easy-waf" >&2
echo "  ls -la /run/fail2ban/fail2ban.sock; groups easy-waf; journalctl -u fail2ban -n 30" >&2
exit 1
