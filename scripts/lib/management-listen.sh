#!/usr/bin/env bash
# Management API listen addresses in easy-waf.env — fix stale per-IP binds after DHCP / VM clone.

# easy_waf_default_management_mode
# The installer default keeps cleartext management HTTP disabled.
easy_waf_default_management_mode() {
  printf '%s\n' 'https_loopback'
}

# easy_waf_management_mode_listeners MODE
# Prints HTTP|HTTPS listen values for install-interactive.sh. The secure default is
# https_loopback; legacy loopback HTTP remains available only when explicitly selected.
easy_waf_management_mode_listeners() {
  local mode
  mode="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  case "$mode" in
    https_loopback|secure_loopback)
      printf '%s\n' 'off|127.0.0.1:8443'
      ;;
    loopback|lo|local)
      printf '%s\n' '127.0.0.1:8000|127.0.0.1:8443'
      ;;
    lan_rfc1918|lan)
      printf '%s\n' 'off|0.0.0.0:8443'
      ;;
    *)
      return 2
      ;;
  esac
}

# easy_waf_fixup_management_listen_addrs
# If EASY_WAF_LISTEN_HTTP/HTTPS bind to an IPv4 not on any local interface, rewrite to 0.0.0.0:port.
easy_waf_fixup_management_listen_addrs() {
  local env_file="${1:-/etc/easy-waf/easy-waf.env}"
  [[ -f "$env_file" ]] || return 0
  command -v ip &>/dev/null || return 0

  local key line val host port
  for key in EASY_WAF_LISTEN_HTTP EASY_WAF_LISTEN_HTTPS; do
    line="$(grep -E "^${key}=" "$env_file" 2>/dev/null | tail -n1)" || continue
    val="${line#*=}"
    val="${val%$'\r'}"
    val="${val#\"}"
    val="${val%\"}"
    [[ "$val" == *:* ]] || continue
    case "${val,,}" in
      off|disabled|none|false|0) continue ;;
    esac
    host="${val%:*}"
    port="${val##*:}"
    case "$host" in
      "" | 0.0.0.0 | 127.0.0.1 | :: | "[::]")
        continue
        ;;
    esac
    if ip -4 addr show 2>/dev/null | grep -qE "inet ${host}/"; then
      continue
    fi
    if command -v easy_waf_env_upsert_kv &>/dev/null; then
      easy_waf_env_upsert_kv "$key" "0.0.0.0:${port}"
    else
      local tmp
      tmp="$(mktemp)"
      grep -vE "^${key}=" "$env_file" >"$tmp" || true
      printf '%s=%s\n' "$key" "0.0.0.0:${port}" >>"$tmp"
      install -m 0640 "$tmp" "$env_file"
      rm -f "$tmp"
    fi
    echo "[easy-waf] Fixed ${key}: ${host} is not assigned locally → 0.0.0.0:${port}"
  done
}
