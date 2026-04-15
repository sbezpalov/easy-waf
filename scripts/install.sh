#!/usr/bin/env bash
# Easy Home WAF — appliance installer (Alma/RHEL via dnf; Debian/Ubuntu via apt).
# Run as root: sudo bash scripts/install.sh
#
# Optional CrowdSec + SPOA (non-interactive): EASY_WAF_INSTALL_CROWDSEC=1 (see docs/CROWDSEC.md).
# Interactive setup (LAN-only API, prompts): scripts/install-interactive.sh
#
# Environment (optional):
#   EASY_WAF_STATE_DIR=/var/lib/easy-waf
#   EASY_WAF_INSTALL_OS_PACKAGES=0   — skip OS base packages (default: 1 = HAProxy, firewalld, fail2ban, nginx, curl)
#   EASY_WAF_INSTALL_POSTGRES=0       — skip local PostgreSQL (default: 1 = install server + init + create DB/user; use 0 with external DATABASE_URL)
#   EASY_WAF_ENABLE_SYSTEMD_UNITS=0   — after install, do not systemctl enable --now api+acmed (default: 1)
#   EASY_WAF_DIST_DIR=/path          — pre-built binaries (if set and non-empty, used as-is; else auto-fetch/build → repo dist/)
#   EASY_WAF_SKIP_SYSTEMD=1          — do not copy systemd units or daemon-reload
#   EASY_WAF_REPO_ROOT=/path         — root of git checkout (default: parent of scripts/)
#   EASY_WAF_RELEASE_VERSION=x.y.z   — try GitHub release before building (overrides VERSION file)
#   EASY_WAF_SKIP_BINARY_FETCH=1     — do not download or build; require EASY_WAF_DIST_DIR with binaries
#   EASY_WAF_INSTALL_BUILD_DEPS=0    — do not install golang/make/git via dnf/apt before source build
#   EASY_WAF_FIREWALLD_MGMT_LAN=0     — skip rich rules: TCP management port only from RFC1918 + 127.0.0.0/8 (default: 1 with OS packages)
#   EASY_WAF_FIREWALLD_MGMT_PORTS="8000 8443" — TCP ports for LAN-only rich rules (management UI)
#   EASY_WAF_FIREWALLD_ZONE=public    EASY_WAF_EXTRA_LAN_CIDR= — optional VPN CIDR for firewalld
#   EASY_WAF_INSTALL_CROWDSEC=0|1   — non-interactive CrowdSec + SPOA bouncer (default 0; dnf/apt only; see docs/CROWDSEC.md)
#   EASY_WAF_CROWDSEC_CONSOLE_TOKEN= — optional; passed to: cscli console enroll (when EASY_WAF_INSTALL_CROWDSEC=1)

set -euo pipefail

STATE_DIR="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
CFG_DIR="/etc/easy-waf"
SECRETS_DIR="${STATE_DIR}/secrets"
ACME_WEBROOT="${STATE_DIR}/acme/webroot"
API_BIN="${EASY_WAF_API_BIN:-/usr/sbin/easy-waf-api}"
ACME_BIN="${EASY_WAF_ACME_BIN:-/usr/sbin/easy-waf-acmed}"
LEGACY_BIN="${EASY_WAF_LEGACY_BIN:-/usr/sbin/easy-wafd}"
ADMIN_BIN="${EASY_WAF_ADMIN_BIN:-/usr/sbin/easy-waf-admin}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${EASY_WAF_REPO_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
DIST_DIR="${EASY_WAF_DIST_DIR:-${REPO_ROOT}/dist}"
SYSTEMD_SRC="${REPO_ROOT}/packaging/systemd"

log() { echo "[easy-waf] $*"; }
die() { echo "[easy-waf] ERROR: $*" >&2; exit 1; }

# Windows CRLF in scripts/lib/*.sh breaks bash on Linux ($'\r': command not found).
normalize_lib_scripts_lf() {
  local f
  for f in "${SCRIPT_DIR}/lib"/*.sh; do
    [[ -f "$f" ]] || continue
    sed -i 's/\r$//' "$f" 2>/dev/null || true
  done
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "must run as root"
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    source /etc/os-release
    log "OS: ${NAME:-unknown} ${VERSION_ID:-}"
  fi
}

create_user_and_layout() {
  id easy-waf &>/dev/null || useradd -r -d "$STATE_DIR" -s /sbin/nologin -c "Easy Home WAF" easy-waf
  mkdir -p \
    "${STATE_DIR}/haproxy" \
    "${STATE_DIR}/revisions" \
    "${STATE_DIR}/certs" \
    "${STATE_DIR}/acme" \
    "$ACME_WEBROOT" \
    "$SECRETS_DIR" \
    "$CFG_DIR"
  if [[ -d /etc/haproxy ]]; then
    mkdir -p /etc/haproxy/errors
  fi
  chmod 0750 "$STATE_DIR" || true
  chmod 0700 "$SECRETS_DIR" || true
  chmod 0755 "$ACME_WEBROOT" || true
  chown -R easy-waf:easy-waf "$STATE_DIR" || true
}

install_env_file() {
  if [[ ! -s "$CFG_DIR/easy-waf.env" ]]; then
    if [[ -f "${REPO_ROOT}/configs/defaults/easy-waf.env.example" ]]; then
      install -m 0640 "${REPO_ROOT}/configs/defaults/easy-waf.env.example" "$CFG_DIR/easy-waf.env"
      log "Created $CFG_DIR/easy-waf.env — edit DATABASE_URL and EASY_WAF_ADMIN_TOKEN"
    else
      die "missing configs/defaults/easy-waf.env.example (set EASY_WAF_REPO_ROOT?)"
    fi
  else
    log "Keeping existing $CFG_DIR/easy-waf.env"
  fi
  chown root:easy-waf "$CFG_DIR/easy-waf.env" 2>/dev/null || chmod 0640 "$CFG_DIR/easy-waf.env"
}

# Upsert KEY=value in /etc/easy-waf/easy-waf.env (file must exist).
easy_waf_env_upsert_kv() {
  local key="$1" val="$2"
  local env_file="$CFG_DIR/easy-waf.env"
  if [[ ! -f "$env_file" ]]; then
    log "WARNING: missing $env_file — cannot set $key"
    return 1
  fi
  local tmp
  tmp="$(mktemp)"
  grep -vE "^${key}=" "$env_file" >"$tmp" || true
  printf '%s=%s\n' "$key" "$val" >>"$tmp"
  install -m 0640 "$tmp" "$env_file"
  rm -f "$tmp"
  chown root:easy-waf "$env_file" 2>/dev/null || true
}

# Delete CrowdSec bouncer if present, then add; print raw API key (one line).
easy_waf_cscli_bouncer_recreate_raw() {
  local name="$1"
  cscli bouncers delete "$name" 2>/dev/null || true
  cscli bouncers add "$name" -o raw
}

# Optional CrowdSec + HAProxy SPOA bouncer (EASY_WAF_INSTALL_CROWDSEC=1). Non-fatal on repo/LAPI/SPOA issues.
easy_waf_install_crowdsec_optional() {
  if [[ "${EASY_WAF_INSTALL_CROWDSEC:-0}" != "1" ]]; then
    return 0
  fi
  case "${EASY_WAF_PKG_MGR:-}" in
    dnf | apt) ;;
    *)
      log "WARNING: EASY_WAF_INSTALL_CROWDSEC=1 but package manager is not dnf/apt — skip CrowdSec"
      return 0
      ;;
  esac

  # shellcheck source=lib/crowdsec-install.sh
  source "${SCRIPT_DIR}/lib/crowdsec-install.sh"

  if ! crowdsec_add_packagecloud_repo; then
    log "WARNING: CrowdSec packagecloud repo setup failed — skip CrowdSec (see docs/CROWDSEC.md)"
    return 0
  fi

  if ! crowdsec_install_agent_package; then
    log "WARNING: CrowdSec agent package install failed — skip CrowdSec"
    return 0
  fi

  crowdsec_start_agent

  if ! crowdsec_wait_lapi; then
    log "WARNING: CrowdSec LAPI not ready — skip bouncers and SPOA (check: systemctl status crowdsec)"
    return 0
  fi

  local enroll="${EASY_WAF_CROWDSEC_CONSOLE_TOKEN:-}"
  if [[ -n "${enroll// }" ]]; then
    crowdsec_console_enroll "$enroll" || log "WARNING: cscli console enroll failed (optional)"
  fi

  if ! command -v cscli &>/dev/null; then
    log "WARNING: cscli not found — skip bouncers"
    return 0
  fi

  local spoa_key api_key
  spoa_key="$(easy_waf_cscli_bouncer_recreate_raw easy-waf-spoa | tr -d '\r\n')" || spoa_key=""
  api_key="$(easy_waf_cscli_bouncer_recreate_raw easy-waf-api | tr -d '\r\n')" || api_key=""
  if [[ -z "$spoa_key" ]] || [[ -z "$api_key" ]]; then
    log "WARNING: bouncer registration incomplete (easy-waf-spoa / easy-waf-api) — check: cscli bouncers list"
  fi

  if crowdsec_install_spoa_bouncer_package; then
    if [[ -n "$spoa_key" ]] && ! crowdsec_inject_spoa_api_key "$spoa_key"; then
      log "WARNING: could not inject SPOA api_key into bouncer yaml"
    fi
    if systemctl enable --now crowdsec-haproxy-spoa-bouncer 2>/dev/null; then
      systemctl restart crowdsec-haproxy-spoa-bouncer 2>/dev/null || true
    else
      log "WARNING: crowdsec-haproxy-spoa-bouncer service not enabled/started"
    fi
  else
    log "WARNING: crowdsec-haproxy-spoa-bouncer package install failed"
  fi

  easy_waf_env_upsert_kv "CROWDSEC_LAPI_URL" "http://127.0.0.1:8080" || true
  if [[ -n "$api_key" ]]; then
    easy_waf_env_upsert_kv "CROWDSEC_LAPI_KEY" "$api_key" || true
    log "Wrote CROWDSEC_LAPI_KEY to $CFG_DIR/easy-waf.env (bouncer easy-waf-api for API / UI health)"
  fi

  systemctl enable --now crowdsec 2>/dev/null || log "WARNING: systemctl enable --now crowdsec failed"
}

# After local PostgreSQL is installed: wait for the daemon, create role/db (idempotent), rotate weak default password in DATABASE_URL.
setup_local_postgres_database() {
  if [[ "${EASY_WAF_INSTALL_POSTGRES:-1}" != "1" ]]; then
    return 0
  fi
  local env_file="$CFG_DIR/easy-waf.env"
  [[ -f "$env_file" ]] || {
    log "WARNING: missing $env_file — skip local DB provisioning"
    return 0
  }

  log "Waiting for PostgreSQL to accept connections..."
  local i=0
  while ! sudo -u postgres pg_isready -q 2>/dev/null; do
    i=$((i + 1))
    if [[ "$i" -gt 90 ]]; then
      log "WARNING: PostgreSQL not ready after 90s — create role/database manually (docs/DEPLOYMENT.md)"
      return 0
    fi
    sleep 1
  done

  # Alma/RHEL default pg_hba often uses "ident" for 127.0.0.1; apps use password (DATABASE_URL) → FATAL Ident authentication failed
  # shellcheck source=lib/pg-hba-easywaf.sh
  source "${SCRIPT_DIR}/lib/pg-hba-easywaf.sh"
  easy_waf_insert_pg_hba_for_easywaf ""

  log "Ensuring PostgreSQL role and database (easywaf / easywaf)…"
  sudo -u postgres createuser -D -R -S easywaf 2>/dev/null || true
  sudo -u postgres createdb -O easywaf easywaf 2>/dev/null || true

  if [[ "${EASY_WAF_ROTATE_WEAK_DB_PASSWORD:-1}" == "1" ]]; then
    # shellcheck source=lib/db-password.sh
    source "${SCRIPT_DIR}/lib/db-password.sh"
    easy_waf_maybe_rotate_weak_db_password "$env_file"
  fi
}

# Plug-and-play: populate REPO_ROOT/dist — try GitHub release, else install toolchain + make build.
acquire_dist_binaries() {
  mkdir -p "${REPO_ROOT}/dist"

  if [[ -f "${DIST_DIR}/easy-waf-api" ]]; then
    log "Using existing binaries: $DIST_DIR/easy-waf-api"
    return 0
  fi

  if [[ "${EASY_WAF_SKIP_BINARY_FETCH:-0}" == "1" ]]; then
    log "EASY_WAF_SKIP_BINARY_FETCH=1 — place easy-waf-api in EASY_WAF_DIST_DIR=$DIST_DIR"
    return 0
  fi

  DIST_DIR="${REPO_ROOT}/dist"

  local ver="${EASY_WAF_RELEASE_VERSION:-}"
  if [[ -z "$ver" ]] && [[ -f "${REPO_ROOT}/VERSION" ]]; then
    ver="$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+' "${REPO_ROOT}/VERSION" | head -1 | tr -d '[:space:]')"
  fi

  if [[ -n "$ver" ]] && [[ "$ver" != "0.0.0-dev" ]] && command -v curl &>/dev/null; then
    local gh="${EASY_WAF_GITHUB_REPO:-easy-waf/easy-waf}"
    local url="https://github.com/${gh}/releases/download/v${ver}/easy-waf_${ver}_linux_amd64.tar.gz"
    log "Trying GitHub release download: $url"
    if curl -fsSL -o /tmp/easy-waf-rel.tgz "$url" 2>/dev/null; then
      tar -xzf /tmp/easy-waf-rel.tgz -C "$DIST_DIR" 2>/dev/null || tar -xzf /tmp/easy-waf-rel.tgz -C "$DIST_DIR" --strip-components=1 2>/dev/null || true
      rm -f /tmp/easy-waf-rel.tgz
      if [[ -f "${DIST_DIR}/easy-waf-api" ]]; then
        log "Downloaded release v${ver} → $DIST_DIR"
        return 0
      fi
    fi
    log "Release v${ver} not found — building from source..."
  else
    log "No public release version (see VERSION / EASY_WAF_RELEASE_VERSION) — building from source..."
  fi

  [[ -f "${REPO_ROOT}/Makefile" ]] || die "No Makefile in $REPO_ROOT — clone full repo or set EASY_WAF_DIST_DIR to pre-built binaries"

  if [[ "${EASY_WAF_INSTALL_BUILD_DEPS:-1}" == "1" ]]; then
    case "${EASY_WAF_PKG_MGR:-}" in
      dnf)
        log "Installing build toolchain (golang, make, git) via dnf..."
        dnf install -y golang make git ca-certificates curl 2>/dev/null || dnf install -y go-toolset make git ca-certificates curl 2>/dev/null || true
        ;;
      apt)
        easy_waf_apt_get_update
        log "Installing build toolchain (golang, make, git) via apt..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go make git ca-certificates curl 2>/dev/null || true
        if ! easy_waf_go_version_meets 1 22; then
          log "Distro Go is older than 1.22 or missing — bootstrapping Go from go.dev..."
          easy_waf_bootstrap_go_toolchain || die "Go bootstrap failed (network or arch?)"
        fi
        ;;
      *)
        log "No dnf/apt — expecting preinstalled go/make/git for build"
        ;;
    esac
  fi

  command -v go &>/dev/null || die "go not found — install Go 1.22+ (dnf install golang / apt install golang-go, or set EASY_WAF_DIST_DIR)"
  easy_waf_go_version_meets 1 22 || die "go is older than 1.22 — use EASY_WAF_DIST_DIR, install newer Go, or set EASY_WAF_BOOTSTRAP_GO_VERSION"
  command -v make &>/dev/null || die "make not found — install make (dnf/apt)"
  log "Building: go mod tidy && make build in $REPO_ROOT"
  (cd "$REPO_ROOT" && go mod tidy && make build) || die "Build failed — check Go/network, or use EASY_WAF_DIST_DIR with pre-built binaries"
  # Root-owned dist/ breaks later "make build" as normal user — hand back to invoking user.
  if [[ -n "${SUDO_USER:-}" ]] && id "${SUDO_USER}" &>/dev/null; then
    chown -R "${SUDO_USER}:${SUDO_USER}" "${REPO_ROOT}/dist" 2>/dev/null || true
    log "chown ${REPO_ROOT}/dist → ${SUDO_USER} (avoid permission denied on go build without sudo)"
  fi
  [[ -f "${DIST_DIR}/easy-waf-api" ]] || die "Build did not produce $DIST_DIR/easy-waf-api"
  log "Built binaries in $DIST_DIR"
}

install_binaries() {
  local found=0
  if [[ -f "${DIST_DIR}/easy-waf-api" ]]; then
    install -m 0755 "${DIST_DIR}/easy-waf-api" "$API_BIN"
    log "Installed $API_BIN"
    found=1
  fi
  if [[ -f "${DIST_DIR}/easy-waf-acmed" ]]; then
    install -m 0755 "${DIST_DIR}/easy-waf-acmed" "$ACME_BIN"
    log "Installed $ACME_BIN"
    found=1
  fi
  if [[ -f "${DIST_DIR}/easy-wafd" ]]; then
    install -m 0755 "${DIST_DIR}/easy-wafd" "$LEGACY_BIN"
    log "Installed $LEGACY_BIN"
    found=1
  fi
  if [[ -f "${DIST_DIR}/easy-waf-admin" ]]; then
    install -m 0755 "${DIST_DIR}/easy-waf-admin" "$ADMIN_BIN"
    log "Installed $ADMIN_BIN (emergency: management-config, reset-control-panel-access, reset-appliance, factory-reset)"
    found=1
  fi
  if [[ "$found" -eq 0 ]]; then
    cat >&2 <<EOF

[easy-waf] ERROR: no binaries in DIST_DIR=$DIST_DIR

Build from source on this machine (needs Go 1.22+, make):
  cd $REPO_ROOT
  go mod tidy
  make build

Then install (binaries are in dist/):
  sudo EASY_WAF_DIST_DIR=$REPO_ROOT/dist bash $REPO_ROOT/scripts/install.sh

Plug-and-play (default): re-run install — it installs golang via dnf/apt (or go.dev tarball on older Debian) and builds.

Release tarball: extract so dist/ contains easy-waf-api, then:
  sudo EASY_WAF_DIST_DIR=/path/to/extract/dist bash $REPO_ROOT/scripts/install.sh

EOF
    exit 1
  fi
}

install_systemd_units() {
  if [[ "${EASY_WAF_SKIP_SYSTEMD:-0}" == "1" ]]; then
    log "Skipping systemd (EASY_WAF_SKIP_SYSTEMD=1)"
    return 0
  fi
  [[ -d "$SYSTEMD_SRC" ]] || die "missing systemd units: $SYSTEMD_SRC"
  for u in easy-waf-api.service easy-waf-acmed.service easy-wafd.service; do
    if [[ -f "${SYSTEMD_SRC}/${u}" ]]; then
      install -m 0644 "${SYSTEMD_SRC}/${u}" "/etc/systemd/system/${u}"
      log "Installed /etc/systemd/system/${u}"
    fi
  done
  systemctl daemon-reload
  log "Run: systemctl enable --now easy-waf-api.service easy-waf-acmed.service"
}

selinux_restore() {
  if command -v restorecon &>/dev/null; then
    restorecon -RFv "$STATE_DIR" 2>/dev/null || true
    restorecon -Rv "$CFG_DIR" 2>/dev/null || true
  fi
}

install_os_packages() {
  if [[ "${EASY_WAF_INSTALL_OS_PACKAGES:-1}" != "1" ]]; then
    log "Skipping OS packages (EASY_WAF_INSTALL_OS_PACKAGES=0)"
    return 0
  fi

  case "${EASY_WAF_PKG_MGR:-}" in
    dnf)
      log "Installing base OS packages via dnf..."
      dnf install -y \
        haproxy \
        firewalld \
        nginx \
        ca-certificates \
        curl \
        || die "dnf install failed (haproxy/firewalld/nginx)"

      if easy_waf_pkg_installed fail2ban; then
        log "fail2ban already installed"
      elif dnf install -y fail2ban 2>/dev/null; then
        :
      else
        log "fail2ban not in default repos — trying epel-release..."
        dnf install -y epel-release 2>/dev/null || true
        if dnf install -y fail2ban fail2ban-firewalld 2>/dev/null; then
          log "Installed fail2ban from EPEL"
        else
          log "warning: fail2ban unavailable (optional). Install later: dnf install epel-release && dnf install fail2ban"
        fi
      fi

      if [[ "${EASY_WAF_INSTALL_POSTGRES:-1}" == "1" ]]; then
        dnf install -y postgresql-server postgresql || die "postgresql install failed"
        if [[ ! -f /var/lib/pgsql/data/PG_VERSION ]]; then
          postgresql-setup --initdb || true
        fi
        systemctl enable --now postgresql || true
        log "PostgreSQL enabled — next steps create /etc/easy-waf/easy-waf.env and provision DB user/database"
      else
        log "PostgreSQL server not installed (EASY_WAF_INSTALL_POSTGRES=0) — set DATABASE_URL to your external instance"
      fi

      if easy_waf_pkg_installed crowdsec; then
        log "CrowdSec package already installed"
      elif [[ "${EASY_WAF_INSTALL_CROWDSEC:-0}" == "1" ]]; then
        log "CrowdSec packages will be installed when EASY_WAF_INSTALL_CROWDSEC=1 (after easy-waf.env exists)"
      else
        log "CrowdSec: set EASY_WAF_INSTALL_CROWDSEC=1 on install.sh, or run sudo bash scripts/install-interactive.sh (docs/CROWDSEC.md)"
      fi

      systemctl enable --now firewalld 2>/dev/null || systemctl enable firewalld 2>/dev/null || true
      systemctl enable haproxy 2>/dev/null || true
      if easy_waf_pkg_installed fail2ban; then
        systemctl enable fail2ban 2>/dev/null || true
      fi
      log "Enabled haproxy, firewalld (fail2ban if installed); firewalld started if possible"
      ;;
    apt)
      easy_waf_apt_get_update
      log "Installing base OS packages via apt..."
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        haproxy \
        firewalld \
        nginx \
        ca-certificates \
        curl \
        || die "apt install failed (haproxy/firewalld/nginx)"

      if easy_waf_pkg_installed fail2ban; then
        log "fail2ban already installed"
      elif DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban; then
        :
      else
        log "warning: fail2ban unavailable (optional). Install later: apt install fail2ban"
      fi

      if [[ "${EASY_WAF_INSTALL_POSTGRES:-1}" == "1" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib \
          || die "postgresql install failed"
        systemctl enable --now postgresql || true
        log "PostgreSQL enabled (Debian/Ubuntu layout) — ensure /etc/easy-waf/easy-waf.env DATABASE_URL matches your cluster"
      else
        log "PostgreSQL server not installed (EASY_WAF_INSTALL_POSTGRES=0) — set DATABASE_URL to your external instance"
      fi

      if easy_waf_pkg_installed crowdsec; then
        log "CrowdSec package already installed"
      elif [[ "${EASY_WAF_INSTALL_CROWDSEC:-0}" == "1" ]]; then
        log "CrowdSec packages will be installed when EASY_WAF_INSTALL_CROWDSEC=1 (after easy-waf.env exists)"
      else
        log "CrowdSec: set EASY_WAF_INSTALL_CROWDSEC=1 on install.sh, or run sudo bash scripts/install-interactive.sh (docs/CROWDSEC.md)"
      fi

      systemctl enable --now firewalld 2>/dev/null || systemctl enable firewalld 2>/dev/null || true
      systemctl enable haproxy 2>/dev/null || true
      if easy_waf_pkg_installed fail2ban; then
        systemctl enable fail2ban 2>/dev/null || true
      fi
      log "Enabled haproxy, firewalld (fail2ban if installed); firewalld started if possible"
      ;;
    *)
      die "no dnf or apt-get — install haproxy/firewalld/nginx manually or set EASY_WAF_INSTALL_OS_PACKAGES=0 (see docs/DEPLOYMENT.md)"
      ;;
  esac
}

# Rich rules: management HTTP+HTTPS (8000, 8443) only from LAN (RFC1918) + loopback.
configure_firewalld_management_lan() {
  if [[ "${EASY_WAF_INSTALL_OS_PACKAGES:-1}" != "1" ]]; then
    return 0
  fi
  if [[ "${EASY_WAF_FIREWALLD_MGMT_LAN:-1}" != "1" ]]; then
    log "Skipping firewalld management rules (EASY_WAF_FIREWALLD_MGMT_LAN=0)"
    return 0
  fi
  systemctl start firewalld 2>/dev/null || true
  # shellcheck source=lib/firewalld-management-api.sh
  source "${SCRIPT_DIR}/lib/firewalld-management-api.sh"
  easy_waf_firewalld_allow_management_from_private_nets \
    "${EASY_WAF_FIREWALLD_MGMT_PORTS:-8000 8443}" \
    "${EASY_WAF_FIREWALLD_ZONE:-public}" \
    "${EASY_WAF_EXTRA_LAN_CIDR:-}"
}

firewall_hint() {
  log "firewalld: add http/https for edge when ready — firewall-cmd --permanent --add-service=http --add-service=https"
  log "Management UI: EASY_WAF_LISTEN_HTTP=0.0.0.0:8000 EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443 + LAN-only firewalld (see EASY_WAF_FIREWALLD_MGMT_LAN)"
}

main() {
  require_root
  detect_os
  normalize_lib_scripts_lf
  # shellcheck source=lib/os-pkg.sh
  source "${SCRIPT_DIR}/lib/os-pkg.sh"
  easy_waf_detect_pkg_mgr
  log "repo root: $REPO_ROOT (package manager: ${EASY_WAF_PKG_MGR:-none})"
  install_os_packages
  create_user_and_layout
  install_env_file
  easy_waf_install_crowdsec_optional
  setup_local_postgres_database
  acquire_dist_binaries
  install_binaries
  install_systemd_units
  selinux_restore
  configure_firewalld_management_lan
  firewall_hint

  if [[ "${EASY_WAF_ENABLE_SYSTEMD_UNITS:-1}" == "1" ]] && [[ "${EASY_WAF_SKIP_SYSTEMD:-0}" != "1" ]]; then
    if systemctl enable --now easy-waf-api.service easy-waf-acmed.service; then
      log "Enabled and started easy-waf-api and easy-waf-acmed"
    else
      log "WARNING: systemctl enable --now failed — run: sudo systemctl enable --now easy-waf-api easy-waf-acmed"
      log "Then: sudo journalctl -u easy-waf-api -u easy-waf-acmed -n 40 --no-pager"
    fi
  else
    log "Services not started (EASY_WAF_ENABLE_SYSTEMD_UNITS=0 or EASY_WAF_SKIP_SYSTEMD=1)"
    log "Run: sudo systemctl enable --now easy-waf-api easy-waf-acmed"
  fi

  if [[ "${EASY_WAF_INSTALL_POSTGRES:-1}" != "1" ]]; then
    log "Using external DB — ensure $CFG_DIR/easy-waf.env DATABASE_URL is correct"
  fi
  log "Done. UI: http://<lan-ip>:8000 and https://<lan-ip>:8443 (self-signed TLS; firewalld: RFC1918 + 127.0.0.0/8 on 8000+8443)"
}

main "$@"
