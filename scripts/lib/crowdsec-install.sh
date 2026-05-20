#!/usr/bin/env bash
# CrowdSec + HAProxy SPOA bouncer (official packagecloud repo: RPM or DEB).
# Sourced by install-interactive.sh — requires root.

crowdsec_add_packagecloud_repo() {
  command -v curl &>/dev/null || {
    echo "[easy-waf] CrowdSec: install curl first" >&2
    return 1
  }
  if command -v dnf &>/dev/null; then
    curl -sSf "https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.rpm.sh" | bash
  elif command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y --no-install-recommends gnupg ca-certificates curl
    curl -sSf "https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh" | bash
  else
    echo "[easy-waf] CrowdSec: need dnf or apt-get" >&2
    return 1
  fi
}

# Quick check: unit active and LAPI responds (used right after apt install).
crowdsec_apt_probe_healthy() {
  local max="${1:-45}" inner
  for inner in $(seq 1 "$max"); do
    if systemctl is-active --quiet crowdsec.service 2>/dev/null; then
      if curl -sf --max-time 2 "http://127.0.0.1:8080/" >/dev/null 2>&1 ||
        curl -sf --max-time 2 "http://127.0.0.1:8080/v1/watchers/login" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 1
  done
  return 1
}

# Debian postinst starts crowdsec immediately; LAPI can briefly return "Internal server error"
# for watcher auth (SQLite / first hub sync). One-shot apt then succeeds on retry — automate that.
crowdsec_apt_recover_crowdsec_until_healthy() {
  local outer inner
  for outer in $(seq 1 8); do
    DEBIAN_FRONTEND=noninteractive apt-get -f install -y 2>/dev/null || true
    dpkg --configure -a 2>/dev/null || true

    systemctl stop crowdsec.service 2>/dev/null || true
    sleep 2
    systemctl reset-failed crowdsec.service 2>/dev/null || true
    systemctl enable crowdsec.service 2>/dev/null || true
    systemctl start crowdsec.service 2>/dev/null || true

    for inner in $(seq 1 35); do
      if systemctl is-active --quiet crowdsec.service 2>/dev/null; then
        if curl -sf --max-time 2 "http://127.0.0.1:8080/" >/dev/null 2>&1 ||
          curl -sf --max-time 2 "http://127.0.0.1:8080/v1/watchers/login" >/dev/null 2>&1; then
          return 0
        fi
      fi
      sleep 1
    done

    systemctl stop crowdsec.service 2>/dev/null || true
    sleep "$((outer + 1))"
  done
  echo "[easy-waf] CrowdSec: agent did not become healthy after apt/dpkg recovery (see journalctl -u crowdsec)" >&2
  return 1
}

crowdsec_install_agent_package() {
  mkdir -p /etc/haproxy/errors
  if command -v dnf &>/dev/null; then
    dnf install -y crowdsec
  elif command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    # apt may exit non-zero if postinst's systemctl start hits a transient LAPI error — recover, don't ask the operator to re-run.
    if ! apt-get install -y crowdsec; then
      echo "[easy-waf] CrowdSec: apt install crowdsec returned non-zero — finishing dpkg and stabilizing LAPI" >&2
    fi
    if crowdsec_apt_probe_healthy 50; then
      return 0
    fi
    echo "[easy-waf] CrowdSec: LAPI not ready after install — running dpkg/systemd recovery" >&2
    crowdsec_apt_recover_crowdsec_until_healthy
  else
    echo "[easy-waf] CrowdSec: dnf or apt-get not found" >&2
    return 1
  fi
}

crowdsec_install_spoa_bouncer_package() {
  mkdir -p /etc/haproxy/errors
  if command -v dnf &>/dev/null; then
    dnf install -y crowdsec-haproxy-spoa-bouncer
  elif command -v apt-get &>/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y crowdsec-haproxy-spoa-bouncer
  else
    return 1
  fi
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
  systemctl enable crowdsec.service 2>/dev/null || true
  local a
  for a in 1 2 3 4 5; do
    systemctl reset-failed crowdsec.service 2>/dev/null || true
    systemctl start crowdsec.service 2>/dev/null || true
    sleep 2
    if systemctl is-active --quiet crowdsec.service 2>/dev/null; then
      return 0
    fi
    systemctl stop crowdsec.service 2>/dev/null || true
    sleep 2
  done
  systemctl start crowdsec.service 2>/dev/null || true
}

# After package install: units exist but do not run until the operator (or bootstrap) enables them.
crowdsec_leave_stopped_disabled() {
  if ! command -v systemctl &>/dev/null; then
    return 0
  fi
  systemctl stop crowdsec-haproxy-spoa-bouncer.service 2>/dev/null || true
  systemctl stop crowdsec.service 2>/dev/null || true
  systemctl disable crowdsec-haproxy-spoa-bouncer.service 2>/dev/null || true
  systemctl disable crowdsec.service 2>/dev/null || true
}

crowdsec_console_enroll() {
  local token="$1"
  [[ -n "$token" ]] || return 0
  cscli console enroll "$token" || echo "[easy-waf] CrowdSec: console enroll failed (optional)" >&2
}
