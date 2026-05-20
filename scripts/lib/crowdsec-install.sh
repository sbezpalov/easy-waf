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

# True when crowdsec.service is active and LAPI accepts HTTP on :8080.
# Do not use curl -f: LAPI often returns 401/405/404 while healthy; -f treats that as down.
crowdsec_lapi_reachable() {
  systemctl is-active --quiet crowdsec.service 2>/dev/null || return 1
  if command -v cscli &>/dev/null; then
    if cscli lapi status &>/dev/null; then
      return 0
    fi
  fi
  local url code
  for url in "http://127.0.0.1:8080/" "http://127.0.0.1:8080/v1/watchers/login"; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 "$url" 2>/dev/null || echo 000)"
    if [[ "$code" != "000" ]]; then
      return 0
    fi
  done
  return 1
}

# Wait up to max seconds for LAPI (used right after apt install).
crowdsec_apt_probe_healthy() {
  local max="${1:-45}" inner
  for inner in $(seq 1 "$max"); do
    if crowdsec_lapi_reachable; then
      return 0
    fi
    if (( inner % 10 == 0 )); then
      echo "[easy-waf] CrowdSec: waiting for LAPI (${inner}/${max})..." >&2
    fi
    sleep 1
  done
  return 1
}

# Restart crowdsec and wait for LAPI (no apt — for re-runs when the package is already installed).
crowdsec_systemd_recover_until_healthy() {
  local outer inner max_inner=30
  for outer in $(seq 1 4); do
    echo "[easy-waf] CrowdSec: systemd recovery attempt ${outer}/4..." >&2
    systemctl stop crowdsec.service 2>/dev/null || true
    sleep 2
    systemctl reset-failed crowdsec.service 2>/dev/null || true
    systemctl enable crowdsec.service 2>/dev/null || true
    systemctl start crowdsec.service 2>/dev/null || true

    for inner in $(seq 1 "$max_inner"); do
      if crowdsec_lapi_reachable; then
        return 0
      fi
      if (( inner % 10 == 0 )); then
        echo "[easy-waf] CrowdSec: waiting for LAPI (${inner}/${max_inner}, attempt ${outer}/4)..." >&2
      fi
      sleep 1
    done
    sleep "$((outer + 1))"
  done
  echo "[easy-waf] CrowdSec: agent did not become healthy after systemd recovery (see journalctl -u crowdsec)" >&2
  return 1
}

# Debian postinst starts crowdsec immediately; LAPI can briefly error while SQLite/hub settle.
# Run apt/dpkg once, then controlled restarts (fresh install only — re-runs use systemd recovery).
crowdsec_apt_recover_crowdsec_until_healthy() {
  echo "[easy-waf] CrowdSec: finishing dpkg configuration (one apt pass)..." >&2
  DEBIAN_FRONTEND=noninteractive apt-get -f install -y 2>/dev/null || true
  dpkg --configure -a 2>/dev/null || true
  crowdsec_systemd_recover_until_healthy
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
    if [[ "${EASY_WAF_CROWDSEC_AGENT_ALREADY_INSTALLED:-0}" == "1" ]]; then
      echo "[easy-waf] CrowdSec: LAPI not ready — running systemd recovery (agent already installed)" >&2
      crowdsec_systemd_recover_until_healthy
    else
      echo "[easy-waf] CrowdSec: LAPI not ready after install — running dpkg/systemd recovery" >&2
      crowdsec_apt_recover_crowdsec_until_healthy
    fi
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
    if crowdsec_lapi_reachable; then
      return 0
    fi
    if (( i % 10 == 0 )); then
      echo "[easy-waf] CrowdSec: waiting for LAPI (${i}/45)..." >&2
    fi
    sleep 1
  done
  echo "[easy-waf] CrowdSec: LAPI not ready in time — check: systemctl status crowdsec; journalctl -u crowdsec" >&2
  return 1
}

# Debian package crowdsec-haproxy-spoa-bouncer (0.3.x on Ubuntu 24.04) installs
# crowdsec-spoa-bouncer.service; some RPM/docs use crowdsec-haproxy-spoa-bouncer.service.
crowdsec_spoa_bouncer_unit() {
  if [[ -f /usr/lib/systemd/system/crowdsec-spoa-bouncer.service ]] ||
    [[ -f /etc/systemd/system/crowdsec-spoa-bouncer.service ]]; then
    printf '%s\n' crowdsec-spoa-bouncer.service
    return 0
  fi
  if [[ -f /usr/lib/systemd/system/crowdsec-haproxy-spoa-bouncer.service ]] ||
    [[ -f /etc/systemd/system/crowdsec-haproxy-spoa-bouncer.service ]]; then
    printf '%s\n' crowdsec-haproxy-spoa-bouncer.service
    return 0
  fi
  printf '%s\n' crowdsec-spoa-bouncer.service
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
  local spoa_unit
  spoa_unit="$(crowdsec_spoa_bouncer_unit)"
  systemctl stop "$spoa_unit" 2>/dev/null || true
  systemctl stop crowdsec.service 2>/dev/null || true
  systemctl disable "$spoa_unit" 2>/dev/null || true
  systemctl disable crowdsec.service 2>/dev/null || true
}

crowdsec_console_enroll() {
  local token="$1"
  [[ -n "$token" ]] || return 0
  cscli console enroll "$token" || echo "[easy-waf] CrowdSec: console enroll failed (optional)" >&2
}
