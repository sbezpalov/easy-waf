#!/usr/bin/env bash
# Easy Home WAF — interactive appliance setup (Alma/RHEL or Debian/Ubuntu).
# Run as root: sudo bash scripts/install-interactive.sh
#
# Collects: management bind policy (loopback vs LAN-only + firewalld), optional CrowdSec + SPOA,
# optional CrowdSec Console enrollment key, then runs scripts/install.sh.
#
# Non-interactive overrides (optional):
#   EASY_WAF_MGMT_MODE=loopback|lan_rfc1918
#   EASY_WAF_LISTEN_HTTP / EASY_WAF_LISTEN_HTTPS — if unset, derived from mgmt_mode (8000 / 8443)
#   EASY_WAF_INSTALL_CROWDSEC=0|1
#   EASY_WAF_CROWDSEC_CONSOLE_TOKEN=   — optional; passed to: cscli console enroll
#   EASY_WAF_FIREWALLD_MGMT_PORTS="8000 8443"
#   EASY_WAF_FIREWALLD_ZONE=public
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

# shellcheck source=lib/firewalld-management-api.sh
source "${SCRIPT_DIR}/lib/firewalld-management-api.sh"
# shellcheck source=lib/crowdsec-install.sh
source "${SCRIPT_DIR}/lib/crowdsec-install.sh"
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

run_crowdsec_flow() {
  log "Adding CrowdSec package repository..."
  crowdsec_add_packagecloud_repo
  log "Installing CrowdSec agent..."
  crowdsec_install_agent_package
  crowdsec_start_agent
  crowdsec_wait_lapi || die "CrowdSec LAPI unavailable"

  local enroll="${EASY_WAF_CROWDSEC_CONSOLE_TOKEN:-}"
  if [[ -z "$enroll" ]] && [[ -t 0 ]]; then
    enroll="$(prompt "CrowdSec Console enrollment token (empty to skip)" "")"
  fi
  if [[ -n "${enroll// }" ]]; then
    crowdsec_console_enroll "$enroll" || true
  fi

  log "Registering LAPI bouncers..."
  local spoa_key ui_key
  spoa_key="$(cscli bouncers add easy-waf-haproxy-spoa -o raw)"
  ui_key="$(cscli bouncers add easy-waf-management -o raw)"

  log "Installing HAProxy SPOA bouncer package..."
  crowdsec_install_spoa_bouncer_package
  crowdsec_inject_spoa_api_key "$spoa_key" || die "failed to configure SPOA bouncer key"

  systemctl enable --now crowdsec-haproxy-spoa-bouncer || log "warning: could not enable crowdsec-haproxy-spoa-bouncer"
  systemctl restart crowdsec-haproxy-spoa-bouncer 2>/dev/null || true

  upsert_env_kv "CROWDSEC_LAPI_URL" "http://127.0.0.1:8080"
  upsert_env_kv "CROWDSEC_LAPI_KEY" "$ui_key"
  log "Wrote CROWDSEC_LAPI_* to $ENV_FILE (management bouncer key for UI health)"
}

main() {
  require_root
  log "repo root: $REPO_ROOT"

  local mgmt_mode="${EASY_WAF_MGMT_MODE:-}"
  local install_cs="${EASY_WAF_INSTALL_CROWDSEC:-}"
  local fw_ports="${EASY_WAF_FIREWALLD_MGMT_PORTS:-8000 8443}"

  if [[ -z "$mgmt_mode" ]]; then
    mgmt_mode="$(prompt "Management UI bind: loopback (127.0.0.1:8000+8443) or lan_rfc1918 (0.0.0.0 + firewalld on 8000/8443)" "loopback")"
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
    local db url tok
    url="$(prompt "DATABASE_URL (PostgreSQL)" "postgres://easywaf:secret@127.0.0.1:5432/easywaf?sslmode=disable")"
    upsert_env_kv "DATABASE_URL" "$url"
    tok="$(prompt_secret "EASY_WAF_ADMIN_TOKEN (empty to set later)")"
    if [[ -n "$tok" ]]; then
      upsert_env_kv "EASY_WAF_ADMIN_TOKEN" "$tok"
    fi
  fi

  if [[ -z "$install_cs" ]]; then
    install_cs="$(prompt "Install CrowdSec + HAProxy SPOA bouncer (OS packages + LAPI keys)" "n")"
  fi
  install_cs="${install_cs,,}"

  export EASY_WAF_INSTALL_OS_PACKAGES="${EASY_WAF_INSTALL_OS_PACKAGES:-1}"
  if [[ -t 0 ]] && [[ -z "${EASY_WAF_INSTALL_POSTGRES+x}" ]]; then
    local pg
    pg="$(prompt "Install local PostgreSQL via OS packages (recommended; n if DATABASE_URL is external only)" "y")"
    pg="${pg,,}"
    case "$pg" in y|yes|1|true) export EASY_WAF_INSTALL_POSTGRES=1 ;; *) export EASY_WAF_INSTALL_POSTGRES=0 ;; esac
  fi
  log "Running scripts/install.sh (EASY_WAF_INSTALL_OS_PACKAGES=$EASY_WAF_INSTALL_OS_PACKAGES EASY_WAF_INSTALL_POSTGRES=${EASY_WAF_INSTALL_POSTGRES:-1})..."
  bash "${SCRIPT_DIR}/install.sh"

  if [[ "${EASY_WAF_INSTALL_POSTGRES:-0}" == "1" ]] && [[ "${EASY_WAF_ROTATE_WEAK_DB_PASSWORD:-1}" == "1" ]]; then
    easy_waf_maybe_rotate_weak_db_password "$ENV_FILE"
  fi

  case "$mgmt_mode" in
    lan_rfc1918|lan)
      easy_waf_firewalld_allow_management_from_private_nets "$fw_ports" "${EASY_WAF_FIREWALLD_ZONE:-public}" "${EASY_WAF_EXTRA_LAN_CIDR:-}"
      ;;
    *)
      local p
      for p in $fw_ports; do
        easy_waf_firewalld_remove_broad_management_port "$p" "${EASY_WAF_FIREWALLD_ZONE:-public}"
      done
      log "Management: loopback-only — UI on 127.0.0.1:8000 (http) and :8443 (https); use SSH port-forward if needed."
      ;;
  esac

  case "$install_cs" in
    y|yes|1|true)
      run_crowdsec_flow
      ;;
    *)
      log "Skipping CrowdSec install (set EASY_WAF_INSTALL_CROWDSEC=1 to force non-interactive)"
      ;;
  esac

  log "Done. Review $ENV_FILE then: systemctl enable --now easy-waf-api easy-waf-acmed"
}

main "$@"
