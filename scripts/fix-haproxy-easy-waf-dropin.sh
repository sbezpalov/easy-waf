#!/usr/bin/env bash
# Point haproxy.service at the EasyWAF-generated config under EASY_WAF_STATE_DIR (default /var/lib/easy-waf).
# Fixes appliances where HAProxy still loads the stock /etc/haproxy/haproxy.cfg (e.g. port 5000 example).
# On SELinux (Alma/RHEL), labels state/haproxy like /etc/haproxy so haproxy_t can read the config.
#
# Usage: sudo bash scripts/fix-haproxy-easy-waf-dropin.sh
# Env: EASY_WAF_STATE_DIR=/var/lib/easy-waf  EASY_WAF_REPO_ROOT=/path/to/easy-waf  EASY_WAF_ENV_FILE=/etc/easy-waf/easy-waf.env
# Re-renders haproxy.cfg from PostgreSQL via easy-waf-admin apply-edge when available (install new binary from repo if missing).

set -euo pipefail

STATE_DIR="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${EASY_WAF_REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ "$(id -u)" != "0" ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

mkdir -p "${STATE_DIR}/haproxy"
chown easy-waf:easy-waf "${STATE_DIR}/haproxy" 2>/dev/null || true

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

SELINUX_LIB="${SCRIPT_DIR}/lib/selinux-easy-waf-haproxy.sh"
if [[ -f "$SELINUX_LIB" ]]; then
  # shellcheck source=lib/selinux-easy-waf-haproxy.sh
  source "$SELINUX_LIB"
  easy_waf_selinux_label_haproxy_dir "$STATE_DIR"
  echo "[easy-waf] SELinux: labeled ${STATE_DIR}/haproxy (if semanage/restorecon available)"
fi

ENVF="${EASY_WAF_ENV_FILE:-/etc/easy-waf/easy-waf.env}"
ADMIN=""
for cand in /usr/sbin/easy-waf-admin /usr/bin/easy-waf-admin "${REPO_ROOT}/dist/easy-waf-admin"; do
  if [[ -x "$cand" ]]; then
    ADMIN="$cand"
    break
  fi
done
if [[ -n "$ADMIN" ]]; then
  set +e
  ae_out="$("$ADMIN" apply-edge -env-file "$ENVF" -state-dir "$STATE_DIR" 2>&1)"
  ae_ec=$?
  set -e
  if [[ $ae_ec -eq 0 ]]; then
    echo "[easy-waf] $ae_out"
  else
    echo "[easy-waf] WARNING: apply-edge failed (exit $ae_ec). Install current easy-waf-admin (make build && sudo install -m0755 dist/easy-waf-admin /usr/sbin/) or apply from UI." >&2
    echo "$ae_out" >&2
  fi
else
  echo "[easy-waf] WARNING: easy-waf-admin not found — update haproxy.cfg from UI (Apply) or install the binary." >&2
fi

# apply-edge rewrites cfg/maps via atomic rename; new inodes may get var_lib_t — re-apply chcon like /etc/haproxy.
if [[ -f "$SELINUX_LIB" ]]; then
  # shellcheck source=lib/selinux-easy-waf-haproxy.sh
  source "$SELINUX_LIB"
  easy_waf_selinux_label_haproxy_dir "$STATE_DIR"
  echo "[easy-waf] SELinux: relabeled ${STATE_DIR}/haproxy after apply-edge (if chcon available)"
fi

if ! /usr/sbin/haproxy -c -f "$CFG" 2>&1; then
  echo "[easy-waf] ERROR: haproxy -c -f $CFG failed (fix config or AVC: ausearch -m avc -ts recent)" >&2
  exit 1
fi

if systemctl cat haproxy.service >/dev/null 2>&1; then
  if systemctl restart haproxy.service; then
    echo "[easy-waf] haproxy.service restarted"
  else
    echo "[easy-waf] ERROR: haproxy restart failed — journalctl -u haproxy -n 80 --no-pager" >&2
    exit 1
  fi
else
  echo "[easy-waf] WARNING: haproxy.service not found" >&2
fi
