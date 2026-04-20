# shellcheck shell=bash
# Idempotent: HAProxy (user haproxy) reads live cfg/maps and creates admin.sock beside easy-waf-owned files.
# Caller should chown state tree to easy-waf:easy-waf when appropriate.

easy_waf_haproxy_join_group_and_chmod_state() {
  local state_dir="${1:?state dir}"
  mkdir -p "${state_dir}/haproxy" "${state_dir}/revisions" "${state_dir}/certs"
  chmod 0750 "${state_dir}/revisions" "${state_dir}/certs" 2>/dev/null || true
  chmod 0770 "${state_dir}/haproxy" 2>/dev/null || true
  if id haproxy &>/dev/null; then
    if usermod -aG easy-waf haproxy 2>/dev/null; then
      echo "[easy-waf] Added haproxy to easy-waf group for config/socket access"
    fi
  fi
}
