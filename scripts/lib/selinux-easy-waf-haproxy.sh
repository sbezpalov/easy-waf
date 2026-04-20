# shellcheck shell=bash
# Optional: sourced by install.sh and fix-haproxy-easy-waf-dropin.sh when present.
# SELinux (RHEL/Alma): haproxy_t may read/write only paths labeled for HAProxy under /var/lib.

easy_waf_selinux_label_haproxy_dir() {
  local state_dir="${1:?state dir}"
  local hp certs sock
  hp="${state_dir}/haproxy"
  certs="${state_dir}/certs"
  sock="${hp}/admin.sock"

  if [[ ! -d "$hp" ]]; then
    return 0
  fi

  if command -v semanage &>/dev/null; then
    if semanage fcontext -a -t haproxy_var_lib_t "${hp}(/.*)?" 2>/dev/null; then
      :
    else
      semanage fcontext -m -t haproxy_var_lib_t "${hp}(/.*)?" 2>/dev/null || true
    fi
    if [[ -d "$certs" ]]; then
      if semanage fcontext -a -t haproxy_var_lib_t "${certs}(/.*)?" 2>/dev/null; then
        :
      else
        semanage fcontext -m -t haproxy_var_lib_t "${certs}(/.*)?" 2>/dev/null || true
      fi
    fi
    if semanage fcontext -a -t haproxy_var_run_t "${sock}" 2>/dev/null; then
      :
    else
      semanage fcontext -m -t haproxy_var_run_t "${sock}" 2>/dev/null || true
    fi
  fi

  if command -v restorecon &>/dev/null; then
    restorecon -Rv "$hp" 2>/dev/null || true
    if [[ -d "$certs" ]]; then
      restorecon -Rv "$certs" 2>/dev/null || true
    fi
  fi

  if command -v setsebool &>/dev/null; then
    setsebool -P haproxy_connect_any 1 2>/dev/null || true
  fi
}
