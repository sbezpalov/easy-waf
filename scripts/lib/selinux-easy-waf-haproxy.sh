# shellcheck shell=bash
# Optional: sourced by install.sh and fix-haproxy-easy-waf-dropin.sh when present.
# Makes HAProxy able to read generated config/maps under $STATE_DIR/haproxy (SELinux on RHEL/Alma).

easy_waf_selinux_label_haproxy_dir() {
  local state_dir="${1:?state dir}"
  local hp
  hp="${state_dir}/haproxy"
  if [[ ! -d "$hp" ]]; then
    return 0
  fi
  if command -v semanage &>/dev/null; then
    local pat="${hp}(/.*)?"
    # Same contexts as the distro HAProxy config tree (package policy).
    if semanage fcontext -a -e /etc/haproxy "$pat" 2>/dev/null; then
      :
    else
      semanage fcontext -m -e /etc/haproxy "$pat" 2>/dev/null || true
    fi
  fi
  # Do not run restorecon -RFv on $hp: on Alma/RHEL it often relabels files from etc_t to var_lib_t
  # even when an equivalence rule exists, which breaks haproxy_t reading the live config.

  # Match the live distro HAProxy tree (works when equivalence / restorecon do not).
  local ref=/etc/haproxy/haproxy.cfg
  if [[ -f "$ref" ]] && command -v chcon &>/dev/null; then
    if [[ -d /etc/haproxy ]]; then
      chcon --reference=/etc/haproxy "$hp" 2>/dev/null || true
    fi
    find "$hp" -maxdepth 1 ! -type d -print0 2>/dev/null |
      while IFS= read -r -d '' f; do
        chcon --reference="$ref" "$f" 2>/dev/null || true
      done
  fi
}
