#!/usr/bin/env bash
# Firewalld helpers:
#   - Management API (8000/8443): RFC1918 + loopback only (not WAN-wide).
#   - HAProxy edge: http + https services (80/443) on the chosen zone (default public).
# Sourced by install.sh and install-interactive.sh — do not run standalone.

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

# Allow HAProxy public listeners: services http (80/tcp) and https (443/tcp) on $zone.
# Idempotent. If a service is missing on minimal images, falls back to raw ports.
easy_waf_firewalld_allow_edge_http_https() {
  local zone="${1:-public}"
  local services="${2:-http https}"

  command -v firewall-cmd &>/dev/null || {
    echo "[easy-waf] firewalld: firewall-cmd not found; skip edge http/https" >&2
    return 0
  }
  systemctl is-active --quiet firewalld 2>/dev/null || {
    echo "[easy-waf] firewalld: not active; start firewalld to apply edge rules" >&2
    return 0
  }

  local s changed=0
  for s in $services; do
    if firewall-cmd --permanent --zone="$zone" --query-service="$s" &>/dev/null; then
      continue
    fi
    if firewall-cmd --permanent --zone="$zone" --add-service="$s" &>/dev/null; then
      changed=1
      echo "[easy-waf] firewalld: added service ${s} on zone=${zone}"
      continue
    fi
    # Fallback: predefined service missing (unusual).
    case "$s" in
      http)
        if ! firewall-cmd --permanent --zone="$zone" --query-port=80/tcp &>/dev/null; then
          if firewall-cmd --permanent --zone="$zone" --add-port=80/tcp &>/dev/null; then
            changed=1
            echo "[easy-waf] firewalld: added port 80/tcp (http service unavailable) on zone=${zone}"
          fi
        fi
        ;;
      https)
        if ! firewall-cmd --permanent --zone="$zone" --query-port=443/tcp &>/dev/null; then
          if firewall-cmd --permanent --zone="$zone" --add-port=443/tcp &>/dev/null; then
            changed=1
            echo "[easy-waf] firewalld: added port 443/tcp (https service unavailable) on zone=${zone}"
          fi
        fi
        ;;
      *)
        echo "[easy-waf] firewalld: unknown edge service '${s}' (expected http https); skip" >&2
        ;;
    esac
  done

  if [[ "$changed" -eq 1 ]]; then
    if firewall-cmd --reload; then
      echo "[easy-waf] firewalld: reloaded — HAProxy edge tcp/80+443 on zone=${zone}"
    fi
  else
    echo "[easy-waf] firewalld: HAProxy edge (http/https) already configured on zone=${zone}"
  fi
}
