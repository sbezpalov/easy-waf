# shellcheck shell=bash
# Optional: sourced by install.sh and fix-haproxy-easy-waf-dropin.sh when present.
# Makes HAProxy able to read generated config/maps under $STATE_DIR/haproxy (SELinux on RHEL/Alma).

easy_waf_selinux_label_haproxy_dir() {
  local state_dir="${1:?state dir}"
  local hp
  hp="${state_dir}/haproxy"
  if ! command -v semanage &>/dev/null || ! command -v restorecon &>/dev/null; then
    return 0
  fi
  if [[ ! -d "$hp" ]]; then
    return 0
  fi
  local pat="${hp}(/.*)?"
  # Same contexts as the distro HAProxy config tree (package policy).
  if semanage fcontext -a -e /etc/haproxy "$pat" 2>/dev/null; then
    :
  else
    semanage fcontext -m -e /etc/haproxy "$pat" 2>/dev/null || true
  fi
  restorecon -RFv "$hp" 2>/dev/null || true
}
