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
  if command -v semanage &>/dev/null && command -v restorecon &>/dev/null; then
    local pat="${hp}(/.*)?"
    # Same contexts as the distro HAProxy config tree (package policy).
    if semanage fcontext -a -e /etc/haproxy "$pat" 2>/dev/null; then
      :
    else
      semanage fcontext -m -e /etc/haproxy "$pat" 2>/dev/null || true
    fi
    restorecon -RFv "$hp" 2>/dev/null || true
  fi

  # If equivalence rules did not apply (policy mismatch), match the live distro config label.
  local ref=/etc/haproxy/haproxy.cfg
  if [[ -f "$ref" ]] && command -v chcon &>/dev/null; then
    find "$hp" -maxdepth 1 -type f \( -name '*.cfg' -o -name '*.txt' -o -name '*.map' \) -print0 2>/dev/null |
      while IFS= read -r -d '' f; do
        chcon --reference="$ref" "$f" 2>/dev/null || true
      done
  fi
}
