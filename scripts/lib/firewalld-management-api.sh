#!/usr/bin/env bash
# Firewalld helpers: expose management API (default 8443/tcp) only from LAN, not from WAN.
# Sourced by install-interactive.sh — do not run standalone.

easy_waf_firewalld_remove_broad_management_port() {
  local port="${1:-8443}"
  local zone="${2:-public}"
  command -v firewall-cmd &>/dev/null || return 0
  systemctl is-active --quiet firewalld 2>/dev/null || return 0
  # Avoid firewalld journal noise (NOT_ENABLED) when the port was never opened as a plain --add-port.
  if firewall-cmd --permanent --zone="$zone" --query-port="${port}/tcp" &>/dev/null; then
    firewall-cmd --permanent --zone="$zone" --remove-port="${port}/tcp" &>/dev/null || true
  fi
}

# Allow TCP ports (space-separated, default "8000 8443") only from RFC1918 + 127.0.0.0/8 on $zone.
easy_waf_firewalld_allow_management_from_private_nets() {
  local ports="${1:-8000 8443}"
  local zone="${2:-public}"
  local extra_cidr="${3:-}"

  command -v firewall-cmd &>/dev/null || {
    echo "[easy-waf] firewalld: firewall-cmd not found; skip LAN-only rules" >&2
    return 0
  }
  systemctl is-active --quiet firewalld 2>/dev/null || {
    echo "[easy-waf] firewalld: not active; start firewalld before using LAN-only API rules" >&2
    return 0
  }

  local p
  for p in $ports; do
    easy_waf_firewalld_remove_broad_management_port "$p" "$zone"
  done

  # Loopback + RFC1918 (API also enforces management_allowed_cidrs in app layer).
  local nets=(127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
  if [[ -n "$extra_cidr" ]]; then
    nets+=("$extra_cidr")
  fi

  local n
  for p in $ports; do
    for n in "${nets[@]}"; do
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule="rule family=ipv4 source address=${n} port port=${p} protocol=tcp accept" \
        || echo "[easy-waf] firewalld: failed to add rule port=${p} net=${n}" >&2
    done
  done

  if firewall-cmd --reload; then
    echo "[easy-waf] firewalld: management TCP ports [${ports// /,}] allowed from RFC1918${extra_cidr:+ + ${extra_cidr}} on zone=${zone}"
  fi
}
