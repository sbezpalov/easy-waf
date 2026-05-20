#!/usr/bin/env bash
# Root-only helper for easy-waf host management API (invoked via sudo -n).
set -euo pipefail

log() { echo "[easy-waf-host] $*" >&2; }

allowed_systemd_unit() {
  case "$1" in
    easy-waf-api.service|easy-waf-acmed.service|haproxy.service|crowdsec.service| \
    crowdsec-haproxy-spoa-bouncer.service|fail2ban.service|nftables.service|postgresql.service)
      return 0
      ;;
  esac
  return 1
}

cmd_nft_apply() {
  local rules="/etc/nftables/easy-waf.nft"
  [[ -f "$rules" ]] || { log "missing $rules"; exit 1; }
  nft -c -f "$rules"
  nft -f "$rules"
}

cmd_nft_install() {
  local src="$1"
  [[ -f "$src" ]] || exit 1
  nft -c -f "$src"
  install -m 0644 "$src" /etc/nftables/easy-waf.nft
  nft -f /etc/nftables/easy-waf.nft
}

cmd_nft_list() {
  nft list ruleset
}

cmd_netplan_apply() {
  if command -v netplan &>/dev/null; then
    netplan apply
  else
    log "netplan not installed"
    exit 1
  fi
}

cmd_netplan_install() {
  local src="$1"
  [[ -f "$src" ]] || exit 1
  mkdir -p /var/lib/easy-waf/netplan-backup
  if [[ -f /etc/netplan/99-easy-waf.yaml ]]; then
    cp -a /etc/netplan/99-easy-waf.yaml "/var/lib/easy-waf/netplan-backup/99-easy-waf.yaml.$(date -u +%Y%m%d%H%M%S)" || true
  fi
  install -m 0600 "$src" /etc/netplan/99-easy-waf.yaml
  netplan apply
}

cmd_systemctl() {
  local action="$1" unit="$2"
  allowed_systemd_unit "$unit" || { log "unit not allowed: $unit"; exit 1; }
  case "$action" in
    start|stop|restart|reload|enable|disable|try-restart) ;;
    *) log "action not allowed: $action"; exit 1 ;;
  esac
  systemctl "$action" "$unit"
}

cmd_apt_update() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
}

cmd_apt_upgrade() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get upgrade -y -qq
}

cmd_apt_simulate() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get -s upgrade
}

cmd_journal() {
  # Args validated: only flags and unit names, no shell metacharacters.
  local args=("$@")
  local a
  for a in "${args[@]}"; do
    if [[ "$a" =~ [\'\"\;\|\&\$\(\)] ]]; then
      log "invalid journal arg"
      exit 1
    fi
  done
  journalctl "${args[@]}"
}

cmd_reboot() {
  systemctl reboot
}

cmd_poweroff() {
  systemctl poweroff
}

cmd_useradd() {
  local name="$1"
  [[ "$name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || exit 1
  useradd -m -s /bin/bash "$name"
}

cmd_userdel() {
  local name="$1"
  [[ "$name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || exit 1
  [[ "$name" != "root" && "$name" != "easy-waf" ]] || exit 1
  userdel -r "$name"
}

cmd_ssh_authorized_keys() {
  local name="$1" tmp="$2"
  [[ "$name" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || exit 1
  [[ -f "$tmp" ]] || exit 1
  local home dir
  home="$(getent passwd "$name" | cut -d: -f6)"
  [[ -n "$home" ]] || exit 1
  dir="${home}/.ssh"
  install -d -m 0700 -o "$name" -g "$name" "$dir"
  install -m 0600 -o "$name" -g "$name" "$tmp" "${dir}/authorized_keys"
}

main() {
  [[ "$(id -u)" -eq 0 ]] || { log "must run as root"; exit 1; }
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    nft-apply) cmd_nft_apply ;;
    nft-install) cmd_nft_install "$1" ;;
    nft-list) cmd_nft_list ;;
    netplan-apply) cmd_netplan_apply ;;
    netplan-install) cmd_netplan_install "$1" ;;
    systemctl) cmd_systemctl "$1" "$2" ;;
    apt-update) cmd_apt_update ;;
    apt-upgrade) cmd_apt_upgrade ;;
    apt-simulate) cmd_apt_simulate ;;
    journal) cmd_journal "$@" ;;
    reboot) cmd_reboot ;;
    poweroff) cmd_poweroff ;;
    useradd) cmd_useradd "$1" ;;
    userdel) cmd_userdel "$1" ;;
    ssh-authorized-keys) cmd_ssh_authorized_keys "$1" "$2" ;;
    *) log "unknown command: $cmd"; exit 1 ;;
  esac
}

main "$@"
