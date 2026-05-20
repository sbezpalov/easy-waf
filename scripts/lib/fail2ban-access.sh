#!/usr/bin/env bash
# Fail2ban Unix socket access for user easy-waf (easy-waf-api has NoNewPrivileges=true).
# Sourced by scripts/install.sh and scripts/fix-fail2ban-api-access.sh.

easy_waf_fail2ban_log() {
  if declare -F log &>/dev/null; then
    log "$@"
  else
    echo "[easy-waf] $*"
  fi
}

# Ubuntu fail2ban package often has no "fail2ban" group; create it for socket ACLs.
easy_waf_fail2ban_ensure_group() {
  if getent group fail2ban &>/dev/null; then
    return 0
  fi
  if groupadd --system fail2ban 2>/dev/null || groupadd fail2ban 2>/dev/null; then
    easy_waf_fail2ban_log "Created fail2ban group (Ubuntu package does not always provide one)"
    return 0
  fi
  easy_waf_fail2ban_log "WARNING: could not create fail2ban group"
  return 1
}

easy_waf_fail2ban_fix_socket_permissions() {
  local sock dir
  for dir in /var/run/fail2ban /run/fail2ban; do
    [[ -d "$dir" ]] || continue
    chgrp fail2ban "$dir" 2>/dev/null || true
    chmod 710 "$dir" 2>/dev/null || true
    sock="${dir}/fail2ban.sock"
    if [[ -S "$sock" ]]; then
      chgrp fail2ban "$sock" 2>/dev/null || true
      chmod 660 "$sock" 2>/dev/null || true
      easy_waf_fail2ban_log "fail2ban socket: $sock (group fail2ban, mode 660)"
    fi
  done
}

# repo_root: path to easy-waf git checkout (packaging/systemd drop-ins).
easy_waf_install_fail2ban_api_access() {
  local repo_root="${1:?repo_root required}"
  if ! command -v fail2ban-client &>/dev/null; then
    return 0
  fi
  if ! easy_waf_fail2ban_ensure_group; then
    return 0
  fi
  if id easy-waf &>/dev/null; then
    if ! id -nG easy-waf | grep -qw fail2ban; then
      usermod -aG fail2ban easy-waf 2>/dev/null || true
      easy_waf_fail2ban_log "Added easy-waf to fail2ban group"
    fi
  fi
  local f2b_dropin="${repo_root}/packaging/systemd/fail2ban-easy-waf-socket.conf"
  if [[ -f "$f2b_dropin" ]]; then
    mkdir -p /etc/systemd/system/fail2ban.service.d
    install -m 0644 "$f2b_dropin" /etc/systemd/system/fail2ban.service.d/easy-waf-socket.conf
    easy_waf_fail2ban_log "Installed fail2ban.service.d/easy-waf-socket.conf"
  fi
  local api_dropin="${repo_root}/packaging/systemd/easy-waf-api-fail2ban.conf"
  if [[ -f "$api_dropin" ]] && [[ "${EASY_WAF_SKIP_SYSTEMD:-0}" != "1" ]]; then
    mkdir -p /etc/systemd/system/easy-waf-api.service.d
    install -m 0644 "$api_dropin" /etc/systemd/system/easy-waf-api.service.d/fail2ban.conf
    easy_waf_fail2ban_log "Installed easy-waf-api.service.d/fail2ban.conf (SupplementaryGroups=fail2ban)"
  fi
  easy_waf_fail2ban_fix_socket_permissions
  if command -v systemctl &>/dev/null && systemctl is-active fail2ban.service &>/dev/null; then
    systemctl daemon-reload 2>/dev/null || true
    systemctl try-reload-or-restart fail2ban.service 2>/dev/null || systemctl restart fail2ban.service 2>/dev/null || true
    easy_waf_fail2ban_fix_socket_permissions
  fi
}
