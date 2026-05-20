#!/usr/bin/env bash
# Easy Home WAF — interactive appliance setup (Ubuntu).
# Run as root: sudo bash scripts/install-interactive.sh
#
# Collects: management bind policy (loopback vs LAN-only + nftables), optional CrowdSec + SPOA,
# optional CrowdSec Console enrollment key, then runs scripts/install.sh.
#
# Non-interactive overrides (optional):
#   EASY_WAF_MGMT_MODE=loopback|lan_rfc1918
#   EASY_WAF_LISTEN_HTTP / EASY_WAF_LISTEN_HTTPS — if unset, derived from mgmt_mode (8000 / 8443)
#   EASY_WAF_INSTALL_CROWDSEC=0|1       — skip CrowdSec packages when 0 (default 1 in install.sh on dnf/apt)
#   EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0|1 — if set, skips prompt; else TTY prompt for LAPI bootstrap
#   EASY_WAF_CROWDSEC_CONSOLE_TOKEN=   — optional; passed to: cscli console enroll during bootstrap
#   EASY_WAF_NFT_MGMT_PORTS="8000 8443"
#   EASY_WAF_NFT_EDGE=1|0       — open HAProxy 80/443 via nftables (default 1; install.sh)
#   EASY_WAF_EXTRA_LAN_CIDR=10.5.0.0/16  — optional extra source for rich rules (VPN, etc.)
#   EASY_WAF_ROTATE_WEAK_DB_PASSWORD=0|1  — when local PostgreSQL was installed, rotate easywaf:secret / easywaf:easywaf (default 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CFG_DIR="/etc/easy-waf"
ENV_FILE="${CFG_DIR}/easy-waf.env"

# Windows CRLF in scripts/lib/*.sh breaks bash on Linux when sourcing.
for _ew_lib in "${SCRIPT_DIR}/lib"/*.sh; do
  [[ -f "$_ew_lib" ]] || continue
  sed -i 's/\r$//' "$_ew_lib" 2>/dev/null || true
done

# shellcheck source=lib/nftables-easy-waf.sh
source "${SCRIPT_DIR}/lib/nftables-easy-waf.sh"
# shellcheck source=lib/db-password.sh
source "${SCRIPT_DIR}/lib/db-password.sh"

log() { echo "[easy-waf] $*"; }
die() { echo "[easy-waf] ERROR: $*" >&2; exit 1; }

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "must run as root"
}

prompt() {
  local def="$2"
  local __v
  if [[ -t 0 ]]; then
    read -r -p "$1 [${def}]: " __v
    echo "${__v:-$def}"
  else
    echo "$def"
  fi
}

prompt_secret() {
  local __v=""
  if [[ -t 0 ]]; then
    read -r -s -p "$1: " __v
    echo "" >&2
  fi
  echo "$__v"
}

ensure_env_template() {
  mkdir -p "$CFG_DIR"
  id easy-waf &>/dev/null || useradd -r -d /var/lib/easy-waf -s /sbin/nologin -c "Easy Home WAF" easy-waf
  if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "${REPO_ROOT}/configs/defaults/easy-waf.env.example" ]]; then
      install -m 0640 "${REPO_ROOT}/configs/defaults/easy-waf.env.example" "$ENV_FILE"
    else
      die "missing configs/defaults/easy-waf.env.example"
    fi
  fi
  chown root:easy-waf "$ENV_FILE" 2>/dev/null || chmod 0640 "$ENV_FILE"
}

upsert_env_kv() {
  local key="$1"
  local val="$2"
  local tmp
  tmp="$(mktemp)"
  [[ -f "$ENV_FILE" ]] || die "missing $ENV_FILE"
  grep -vE "^${key}=" "$ENV_FILE" >"$tmp" || true
  printf '%s=%s\n' "$key" "$val" >>"$tmp"
  install -m 0640 "$tmp" "$ENV_FILE"
  rm -f "$tmp"
  chown root:easy-waf "$ENV_FILE" 2>/dev/null || true
}

main() {
  require_root
  log "repo root: $REPO_ROOT"

  local mgmt_mode="${EASY_WAF_MGMT_MODE:-}"
  local fw_ports="${EASY_WAF_NFT_MGMT_PORTS:-${EASY_WAF_FIREWALLD_MGMT_PORTS:-8000 8443}}"

  if [[ -z "$mgmt_mode" ]]; then
    mgmt_mode="$(prompt "Management UI bind: loopback (127.0.0.1:8000+8443) or lan_rfc1918 (0.0.0.0 + nftables on 8000/8443)" "loopback")"
  fi
  mgmt_mode="${mgmt_mode,,}"

  ensure_env_template

  if [[ -z "${EASY_WAF_LISTEN_HTTP:-}" ]]; then
    case "$mgmt_mode" in
      loopback|lo|local)
        upsert_env_kv "EASY_WAF_LISTEN_HTTP" "127.0.0.1:8000"
        upsert_env_kv "EASY_WAF_LISTEN_HTTPS" "127.0.0.1:8443"
        ;;
      lan_rfc1918|lan)
        upsert_env_kv "EASY_WAF_LISTEN_HTTP" "0.0.0.0:8000"
        upsert_env_kv "EASY_WAF_LISTEN_HTTPS" "0.0.0.0:8443"
        ;;
      *)
        die "unknown EASY_WAF_MGMT_MODE=$mgmt_mode (use loopback or lan_rfc1918)"
        ;;
    esac
  elif [[ -z "${EASY_WAF_LISTEN_HTTPS:-}" ]]; then
    upsert_env_kv "EASY_WAF_LISTEN_HTTPS" "0.0.0.0:8443"
  fi

  if grep -qE '^EASY_WAF_LISTEN=' "$ENV_FILE" 2>/dev/null; then
    grep -vE '^EASY_WAF_LISTEN=' "$ENV_FILE" >"${ENV_FILE}.tmp" && mv "${ENV_FILE}.tmp" "$ENV_FILE"
    chown root:easy-waf "$ENV_FILE" 2>/dev/null || chmod 0640 "$ENV_FILE"
  fi

  if [[ -t 0 ]]; then
    local url tok
    url="$(prompt "DATABASE_URL (PostgreSQL)" "postgres://easywaf:secret@127.0.0.1:5432/easywaf?sslmode=disable")"
    upsert_env_kv "DATABASE_URL" "$url"
    tok="$(prompt_secret "EASY_WAF_ADMIN_TOKEN (empty to set later)")"
    if [[ -n "$tok" ]]; then
      upsert_env_kv "EASY_WAF_ADMIN_TOKEN" "$tok"
    fi
  fi

  # CrowdSec RPM/DEBs: install.sh defaults to EASY_WAF_INSTALL_CROWDSEC=1 (packages on disk, units stopped/disabled).
  if [[ "${EASY_WAF_INSTALL_CROWDSEC:-1}" == "0" ]]; then
    export EASY_WAF_INSTALL_CROWDSEC=0
    export EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0
  elif [[ -z "${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-}" ]] && [[ -t 0 ]]; then
    local cs_now
    cs_now="$(prompt "Start CrowdSec LAPI now and register bouncer keys (writes CROWDSEC_LAPI_KEY; y/n)" "y")"
    cs_now="${cs_now,,}"
    case "$cs_now" in y|yes|1|true) export EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1 ;; *) export EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0 ;; esac
  fi
  export EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL="${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-1}"

  export EASY_WAF_INSTALL_OS_PACKAGES="${EASY_WAF_INSTALL_OS_PACKAGES:-1}"
  if [[ -t 0 ]] && [[ -z "${EASY_WAF_INSTALL_POSTGRES+x}" ]]; then
    local pg
    pg="$(prompt "Install local PostgreSQL via OS packages (recommended; n if DATABASE_URL is external only)" "y")"
    pg="${pg,,}"
    case "$pg" in y|yes|1|true) export EASY_WAF_INSTALL_POSTGRES=1 ;; *) export EASY_WAF_INSTALL_POSTGRES=0 ;; esac
  fi
  log "Running scripts/install.sh (EASY_WAF_INSTALL_OS_PACKAGES=$EASY_WAF_INSTALL_OS_PACKAGES EASY_WAF_INSTALL_POSTGRES=${EASY_WAF_INSTALL_POSTGRES:-1} EASY_WAF_INSTALL_CROWDSEC=${EASY_WAF_INSTALL_CROWDSEC:-1} EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL})..."
  bash "${SCRIPT_DIR}/install.sh"

  if [[ "${EASY_WAF_INSTALL_POSTGRES:-0}" == "1" ]] && [[ "${EASY_WAF_ROTATE_WEAK_DB_PASSWORD:-1}" == "1" ]]; then
    easy_waf_maybe_rotate_weak_db_password "$ENV_FILE"
  fi

  case "$mgmt_mode" in
    lan_rfc1918|lan)
      export EASY_WAF_NFT_MGMT_LAN=1
      easy_waf_nft_configure_appliance 1 "$fw_ports" "${EASY_WAF_NFT_EDGE:-1}" "${EASY_WAF_EXTRA_LAN_CIDR:-}"
      ;;
    *)
      export EASY_WAF_NFT_MGMT_LAN=0
      easy_waf_nft_configure_appliance 0 "$fw_ports" "${EASY_WAF_NFT_EDGE:-1}" "${EASY_WAF_EXTRA_LAN_CIDR:-}"
      log "Management: loopback-only — UI on 127.0.0.1:8000 (http) and :8443 (https); use SSH port-forward if needed."
      ;;
  esac

  if [[ "${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-0}" != "1" ]] && [[ "${EASY_WAF_INSTALL_CROWDSEC:-1}" == "1" ]]; then
    log "CrowdSec packages are on the host; to start LAPI and keys later: sudo bash scripts/crowdsec-bootstrap-lapi.sh"
  fi

  log "Done. Review $ENV_FILE then: systemctl enable --now easy-waf-api easy-waf-acmed"
}

main "$@"
