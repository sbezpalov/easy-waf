#!/usr/bin/env bash
# Point haproxy.service at the EasyWAF-generated config under EASY_WAF_STATE_DIR (default /var/lib/easy-waf).
# Fixes appliances where HAProxy still loads the stock /etc/haproxy/haproxy.cfg (e.g. port 5000 example).
#
# Usage: sudo bash scripts/fix-haproxy-easy-waf-dropin.sh
# Env: EASY_WAF_STATE_DIR=/var/lib/easy-waf  EASY_WAF_REPO_ROOT=/path/to/easy-waf

set -euo pipefail

STATE_DIR="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${EASY_WAF_REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ "$(id -u)" != "0" ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

mkdir -p /etc/systemd/system/haproxy.service.d
CFG="${STATE_DIR}/haproxy/haproxy.cfg"
BOOT_SRC="${REPO_ROOT}/configs/defaults/haproxy-bootstrap.cfg"
DROP_SRC="${REPO_ROOT}/packaging/systemd/haproxy-easy-waf-dropin.conf"

if [[ ! -f "$DROP_SRC" ]]; then
  echo "ERROR: missing $DROP_SRC (set EASY_WAF_REPO_ROOT?)" >&2
  exit 1
fi

if [[ ! -s "$CFG" ]]; then
  if [[ -f "$BOOT_SRC" ]]; then
    sed "s|__EASY_WAF_STATE__|${STATE_DIR}|g" "$BOOT_SRC" >"${CFG}.tmp"
    install -m 0640 -o easy-waf -g easy-waf "${CFG}.tmp" "$CFG"
    rm -f "${CFG}.tmp"
    echo "[easy-waf] installed bootstrap $CFG"
  else
    echo "ERROR: no existing $CFG and missing bootstrap $BOOT_SRC" >&2
    exit 1
  fi
fi

sed "s|__EASY_WAF_STATE__|${STATE_DIR}|g" "$DROP_SRC" >/etc/systemd/system/haproxy.service.d/50-easy-waf.conf
chmod 0644 /etc/systemd/system/haproxy.service.d/50-easy-waf.conf
echo "[easy-waf] wrote /etc/systemd/system/haproxy.service.d/50-easy-waf.conf"

systemctl daemon-reload
if systemctl cat haproxy.service >/dev/null 2>&1; then
  if systemctl try-restart haproxy.service; then
    echo "[easy-waf] haproxy.service restarted"
  else
    echo "[easy-waf] ERROR: haproxy restart failed — journalctl -u haproxy -n 50 --no-pager" >&2
    exit 1
  fi
else
  echo "[easy-waf] WARNING: haproxy.service not found" >&2
fi
