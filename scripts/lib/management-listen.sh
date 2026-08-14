#!/usr/bin/env bash
# Management API listen addresses in easy-waf.env — fix stale per-IP binds after DHCP / VM clone.

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
