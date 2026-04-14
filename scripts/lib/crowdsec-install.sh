#!/usr/bin/env bash
# CrowdSec + HAProxy SPOA bouncer (RHEL/Alma/Fedora via official packagecloud repo).
# Sourced by install-interactive.sh — requires root.

crowdsec_add_packagecloud_repo() {
  command -v curl &>/dev/null || {
    echo "[easy-waf] CrowdSec: install curl first" >&2
    return 1
  }
  local url="https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh"
  curl -sSf "$url" | bash
}

crowdsec_install_agent_package() {
  command -v dnf &>/dev/null || {
    echo "[easy-waf] CrowdSec: dnf not found" >&2
    return 1
  }
  mkdir -p /etc/haproxy/errors
  dnf install -y crowdsec
}

crowdsec_install_spoa_bouncer_package() {
  command -v dnf &>/dev/null || return 1
  mkdir -p /etc/haproxy/errors
  dnf install -y crowdsec-haproxy-spoa-bouncer
}

crowdsec_wait_lapi() {
  local i
  for i in $(seq 1 45); do
    if command -v cscli &>/dev/null && cscli version &>/dev/null; then
      if curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:8080/" 2>/dev/null || \
         curl -sf -o /dev/null --max-time 2 "http://127.0.0.1:8080/v1/watchers/login" 2>/dev/null; then
        return 0
      fi
    fi
    sleep 1
  done
  echo "[easy-waf] CrowdSec: LAPI not ready in time — check: systemctl status crowdsec; journalctl -u crowdsec" >&2
  return 1
}

crowdsec_inject_spoa_api_key() {
  local key="$1"
  local yaml="/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml"
  [[ -f "$yaml" ]] || {
    echo "[easy-waf] CrowdSec: missing $yaml" >&2
    return 1
  }
  if ! grep -qE '^[[:space:]]*api_key:' "$yaml"; then
    echo "[easy-waf] CrowdSec: could not find api_key in $yaml — set key manually" >&2
    return 1
  fi
  if command -v perl &>/dev/null; then
    KEY="$key" perl -i -pe 's/^(\s*)api_key:\s*.*/$1api_key: $ENV{KEY}/' "$yaml"
  else
    local esc
    esc=$(printf '%s\n' "$key" | sed 's/[&/\]/\\&/g')
    sed -i "s/^[[:space:]]*api_key:.*/api_key: ${esc}/" "$yaml"
  fi
}

crowdsec_start_agent() {
  systemctl enable --now crowdsec
}

crowdsec_console_enroll() {
  local token="$1"
  [[ -n "$token" ]] || return 0
  cscli console enroll "$token" || echo "[easy-waf] CrowdSec: console enroll failed (optional)" >&2
}
