#!/usr/bin/env bash
# Easy Home WAF — appliance installer (Ubuntu via apt).
# Run as root: sudo bash scripts/install.sh
#
# CrowdSec + HAProxy SPOA bouncer: installed by default on dnf/apt (see docs/CROWDSEC.md).
# Interactive setup (LAN-only API, prompts): scripts/install-interactive.sh
#
# Environment (optional):
#   EASY_WAF_STATE_DIR=/var/lib/easy-waf
#   EASY_WAF_INSTALL_OS_PACKAGES=0   — skip OS base packages (default: 1 = HAProxy, nftables, fail2ban, curl)
#   EASY_WAF_INSTALL_POSTGRES=0       — skip local PostgreSQL (default: 1 = install server + init + create DB/user; use 0 with external DATABASE_URL)
#   EASY_WAF_ENABLE_SYSTEMD_UNITS=0   — after install, do not systemctl enable --now api+acmed (default: 1)
#   EASY_WAF_DIST_DIR=/path          — pre-built binaries (if set and non-empty, used as-is; else auto-fetch/build → repo dist/)
#   EASY_WAF_SKIP_SYSTEMD=1          — do not copy systemd units or daemon-reload
#   EASY_WAF_REPO_ROOT=/path         — root of git checkout (default: parent of scripts/)
#   EASY_WAF_RELEASE_VERSION=x.y.z   — try GitHub release before building (overrides VERSION file)
#   EASY_WAF_SKIP_BINARY_FETCH=1     — do not download or build; require EASY_WAF_DIST_DIR with binaries
#   EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — install a release tarball whose SHA256SUMS entry is missing or mismatched (discouraged; default: refuse and build from source)
#   EASY_WAF_INSTALL_BUILD_DEPS=0    — do not install golang/make/git via apt before source build
#   EASY_WAF_NFT_MGMT_LAN=0         — skip nftables rules for management ports from RFC1918 (default: 1)
#   EASY_WAF_NFT_MGMT_PORTS="8000 8443"
#   EASY_WAF_EXTRA_LAN_CIDR=         — optional extra source CIDR for management ports
#   EASY_WAF_NFT_EDGE=1             — open HAProxy edge tcp/80+443 (default 1)
#   EASY_WAF_NFT_EDGE=0             — skip edge rules in nftables
#   EASY_WAF_INSTALL_CROWDSEC=0|1    — install CrowdSec + SPOA DEB packages (default 1; set 0 to skip)
#   EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0|1 — after packages: start LAPI, register bouncers, write CROWDSEC_* to easy-waf.env (default 1 = full appliance)
#   EASY_WAF_CROWDSEC_CONSOLE_TOKEN= — optional; passed to: cscli console enroll (when bootstrap runs)
#   EASY_WAF_FAIL2BAN_AUTO_START=0|1 — after fail2ban package install: systemctl start (default 1)
#   EASY_WAF_SKIP_HAPROXY_SYSTEMD_DROPIN=1 — do not install haproxy.service.d drop-in (stock /etc config stays in use)

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
    case "${ID:-}" in
      ubuntu|debian) ;;
      *)
        log "WARNING: Easy Home WAF is tested on Ubuntu 24.04 LTS only."
        log "Other distributions may work but are not officially supported."
        ;;
    esac
  fi
}

create_user_and_layout() {
  id easy-waf &>/dev/null || useradd -r -d "$STATE_DIR" -s /sbin/nologin -c "Easy Home WAF" easy-waf
  mkdir -p \
    "${STATE_DIR}/haproxy" \
    "${STATE_DIR}/revisions" \
    "${STATE_DIR}/certs" \
    "${STATE_DIR}/acme" \
    "${STATE_DIR}/geoip" \
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
  # geoip/ must stay writable by easy-waf: the API installs uploaded GeoLite2
  # databases there (POST /api/v1/geoip/database) by renaming into this directory.
  chmod 0750 "${STATE_DIR}/haproxy" "${STATE_DIR}/certs" "${STATE_DIR}/revisions" "${STATE_DIR}/geoip" 2>/dev/null || true
  if id haproxy &>/dev/null; then
    if ! id -nG haproxy | grep -qw easy-waf; then
      usermod -aG easy-waf haproxy
      log "Added haproxy to easy-waf group (read config + certs)"
    fi
  fi
  if id easy-waf &>/dev/null && id haproxy &>/dev/null; then
    if ! id -nG easy-waf | grep -qw haproxy; then
      usermod -aG haproxy easy-waf
      log "Added easy-waf to haproxy group (stats socket under /run/haproxy)"
    fi
  fi
}

# /run/haproxy is tmpfs; persist mode/owner via systemd-tmpfiles.
ensure_haproxy_run_dir() {
  local tmpfiles_conf="/etc/tmpfiles.d/easy-waf-haproxy.conf"
  if [[ ! -f "$tmpfiles_conf" ]]; then
    cat >"$tmpfiles_conf" <<'EOF'
# easy-waf: HAProxy stats socket directory (systemd-tmpfiles)
d /run/haproxy 0755 haproxy haproxy -
EOF
    log "Created $tmpfiles_conf for /run/haproxy on boot"
  fi
  mkdir -p /run/haproxy
  chown haproxy:haproxy /run/haproxy 2>/dev/null || true
  chmod 0755 /run/haproxy 2>/dev/null || true
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

# When NFT_* (or legacy FIREWALLD_*) were not exported, read from easy-waf.env.
easy_waf_load_nft_env_from_file_if_unset() {
  local f="$CFG_DIR/easy-waf.env"
  [[ -f "$f" ]] || return 0
  local key line val
  for key in EASY_WAF_NFT_EDGE EASY_WAF_NFT_MGMT_LAN EASY_WAF_NFT_MGMT_PORTS EASY_WAF_EXTRA_LAN_CIDR \
    EASY_WAF_FIREWALLD_EDGE EASY_WAF_FIREWALLD_MGMT_LAN EASY_WAF_FIREWALLD_MGMT_PORTS; do
    if printenv "$key" &>/dev/null; then
      continue
    fi
    line="$(grep -E "^${key}=" "$f" 2>/dev/null | tail -n1)" || true
    [[ -z "$line" ]] && continue
    val="${line#*=}"
    val="${val%$'\r'}"
    if [[ ${#val} -ge 2 && "${val:0:1}" == '"' && "${val: -1}" == '"' ]]; then
      val="${val:1:${#val}-2}"
    fi
    # declare -g handles values with spaces (e.g. EDGE_SERVICES="http https")
    declare -gx "${key}=${val}"
  done
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

# GET /v1/decisions with bouncer key (CrowdSec expects X-Api-Key, not Bearer).
easy_waf_crowdsec_decisions_check() {
  local api_key="$1" attempt code lapi_url="http://127.0.0.1:8080"
  api_key="$(printf '%s' "$api_key" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [[ -n "$api_key" ]] || return 1
  for attempt in 1 2 3 4 5; do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
      -H "X-Api-Key: ${api_key}" "${lapi_url}/v1/decisions?limit=1" 2>/dev/null || echo 000)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    if [[ "$attempt" -lt 5 ]]; then
      sleep 2
    fi
  done
  log "WARNING: LAPI decisions HTTP ${code} after ${attempt} attempts (expected 200); journalctl -u crowdsec -n 40"
  return 1
}

# Delete CrowdSec bouncer if present, then add; print raw API key (one line).
easy_waf_cscli_bouncer_recreate_raw() {
  local name="$1"
  cscli bouncers delete "$name" 2>/dev/null || true
  cscli bouncers add "$name" -o raw
}

# Install CrowdSec + SPOA bouncer packages; on first agent install leave units disabled/stopped (idempotent re-runs do not stop a running LAPI).
easy_waf_install_crowdsec_packages() {
  if [[ "${EASY_WAF_INSTALL_CROWDSEC:-1}" != "1" ]]; then
    return 0
  fi
  case "${EASY_WAF_PKG_MGR:-}" in
    apt) ;;
    *)
      log "WARNING: CrowdSec packages skipped — apt not available (set EASY_WAF_INSTALL_CROWDSEC=0 to silence)"
      return 0
      ;;
  esac

  local had_crowdsec_agent=0
  easy_waf_pkg_installed crowdsec && had_crowdsec_agent=1

  # shellcheck source=lib/crowdsec-install.sh
  source "${SCRIPT_DIR}/lib/crowdsec-install.sh"

  if ! crowdsec_add_packagecloud_repo; then
    log "ERROR: CrowdSec packagecloud repo setup failed — appliance stack incomplete (need outbound HTTPS; see docs/CROWDSEC.md)"
    log "ERROR: re-run: sudo bash scripts/install.sh  OR  sudo bash scripts/crowdsec-bootstrap-lapi.sh after fixing network"
    return 1
  fi

  if [[ "$had_crowdsec_agent" -eq 1 ]]; then
    export EASY_WAF_CROWDSEC_AGENT_ALREADY_INSTALLED=1
  else
    unset EASY_WAF_CROWDSEC_AGENT_ALREADY_INSTALLED || true
  fi

  if ! crowdsec_install_agent_package; then
    log "ERROR: CrowdSec agent package install failed — appliance stack incomplete (see docs/CROWDSEC.md)"
    return 1
  fi

  if ! crowdsec_install_spoa_bouncer_package; then
    if [[ "${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-1}" == "1" ]]; then
      log "ERROR: crowdsec-haproxy-spoa-bouncer package install failed (required for appliance SPOE; see docs/CROWDSEC.md)"
      return 1
    fi
    log "WARNING: crowdsec-haproxy-spoa-bouncer package install failed (CrowdSec agent is installed)"
  fi

  if [[ "$had_crowdsec_agent" -eq 0 ]] && [[ "${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-1}" != "1" ]]; then
    crowdsec_leave_stopped_disabled
    log "CrowdSec packages installed; units disabled/stopped (AUTO_START=0). Run: sudo bash scripts/crowdsec-bootstrap-lapi.sh"
  else
    log "CrowdSec packages ready; bootstrap will register bouncers and start LAPI/SPOA (AUTO_START=${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-1})"
  fi
  return 0
}

# Start LAPI, register bouncers, inject SPOA key, enable SPOA bouncer, write CROWDSEC_*.
# Returns 0 on success; 1 when AUTO_START=1 and appliance CrowdSec integration is incomplete.
easy_waf_bootstrap_crowdsec_lapi() {
  if [[ "${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-1}" != "1" ]]; then
    return 0
  fi
  if [[ "${EASY_WAF_INSTALL_CROWDSEC:-1}" != "1" ]]; then
    return 0
  fi
  case "${EASY_WAF_PKG_MGR:-}" in
    apt) ;;
    *) return 0 ;;
  esac

  # shellcheck source=lib/crowdsec-install.sh
  source "${SCRIPT_DIR}/lib/crowdsec-install.sh"

  if ! command -v cscli &>/dev/null; then
    log "ERROR: CrowdSec bootstrap failed — cscli missing (install crowdsec package)"
    return 1
  fi

  crowdsec_start_agent

  if ! crowdsec_wait_lapi; then
    log "ERROR: CrowdSec LAPI not ready — check: systemctl status crowdsec; journalctl -u crowdsec"
    return 1
  fi

  local enroll="${EASY_WAF_CROWDSEC_CONSOLE_TOKEN:-}"
  if [[ -n "${enroll// }" ]]; then
    crowdsec_console_enroll "$enroll" || log "WARNING: cscli console enroll failed (optional)"
  fi

  if [[ ! -f /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml ]]; then
    log "CrowdSec: SPOA yaml missing — installing crowdsec-haproxy-spoa-bouncer package"
    if ! crowdsec_install_spoa_bouncer_package; then
      log "ERROR: crowdsec-haproxy-spoa-bouncer package required for SPOE (see docs/CROWDSEC.md)"
      return 1
    fi
  fi

  local spoa_key api_key
  spoa_key="$(easy_waf_cscli_bouncer_recreate_raw easy-waf-spoa | tr -d '\r\n')" || spoa_key=""
  api_key="$(easy_waf_cscli_bouncer_recreate_raw easy-waf-api | tr -d '\r\n')" || api_key=""
  if [[ -z "$api_key" ]]; then
    log "ERROR: could not register CrowdSec bouncer easy-waf-api (UI LAPI / decisions need this key)"
    return 1
  fi
  if [[ -z "$spoa_key" ]]; then
    log "ERROR: could not register CrowdSec bouncer easy-waf-spoa (HAProxy SPOE)"
    return 1
  fi

  if ! crowdsec_inject_spoa_api_key "$spoa_key"; then
    log "ERROR: could not inject SPOA api_key into /etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml"
    return 1
  fi

  local spoa_unit
  spoa_unit="$(crowdsec_spoa_bouncer_unit)"
  if ! systemctl enable --now "$spoa_unit" 2>/dev/null; then
    log "ERROR: could not enable $spoa_unit (package crowdsec-haproxy-spoa-bouncer)"
    return 1
  fi
  systemctl restart "$spoa_unit" 2>/dev/null || true

  easy_waf_env_upsert_kv "CROWDSEC_LAPI_URL" "http://127.0.0.1:8080/" || true
  easy_waf_env_upsert_kv "CROWDSEC_LAPI_KEY" "$api_key" || true
  log "Wrote CROWDSEC_LAPI_* to $CFG_DIR/easy-waf.env (bouncer easy-waf-api for UI; no manual cscli needed)"

  if ! easy_waf_crowdsec_decisions_check "$api_key"; then
    log "ERROR: LAPI decisions check failed after bootstrap (GET /v1/decisions with easy-waf-api key; need X-Api-Key)"
    return 1
  fi
  log "CrowdSec LAPI decisions API OK (out-of-box check passed)"
  return 0
}

# Merge easy-waf.env (CrowdSec keys, etc.) into PostgreSQL before first systemctl start — UI works without Settings → Load.
easy_waf_sync_settings_to_db() {
  local api="$API_BIN"
  [[ -x "$api" ]] || api="${DIST_DIR}/easy-waf-api"
  [[ -x "$api" ]] || return 0
  [[ -f "$CFG_DIR/easy-waf.env" ]] || return 0
  grep -q '^DATABASE_URL=' "$CFG_DIR/easy-waf.env" 2>/dev/null || return 0
  set -a
  # shellcheck source=/dev/null
  source "$CFG_DIR/easy-waf.env"
  set +a
  if DATABASE_URL="$DATABASE_URL" EASY_WAF_STATE_DIR="$STATE_DIR" timeout 25 "$api" -sync-settings-only; then
    log "Synced settings from $CFG_DIR/easy-waf.env into PostgreSQL (UI ready without manual import)"
  else
    log "WARNING: settings DB sync failed — easy-waf-api will merge env on first start"
  fi
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

  # Some PostgreSQL installs use peer/ident for 127.0.0.1; apps use password (DATABASE_URL)
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
    local base="https://github.com/${gh}/releases/download/v${ver}"
    local name="easy-waf_${ver}_linux_amd64.tar.gz"
    local url="${base}/${name}"
    # shellcheck source=lib/release-verify.sh
    source "${SCRIPT_DIR}/lib/release-verify.sh"
    local tmpd tgz
    tmpd="$(mktemp -d)" || die "mktemp -d failed"
    tgz="${tmpd}/${name}"
    log "Trying GitHub release download: $url"
    # Binaries land in /usr/sbin as root: never unpack an artifact we could not verify.
    if easy_waf_curl_https -o "$tgz" "$url" 2>/dev/null &&
      easy_waf_verify_release_artifact "$tgz" "$name" "${base}/SHA256SUMS"; then
      tar -xzf "$tgz" -C "$DIST_DIR" 2>/dev/null || tar -xzf "$tgz" -C "$DIST_DIR" --strip-components=1 2>/dev/null || true
      # GitHub release tarball layout: dist/<binaries> (see .github/workflows/release.yml)
      if [[ -f "${DIST_DIR}/dist/easy-waf-api" ]]; then
        for b in easy-waf-hostd easy-waf-api easy-waf-acmed easy-wafd easy-waf-admin; do
          [[ -f "${DIST_DIR}/dist/${b}" ]] && mv -f "${DIST_DIR}/dist/${b}" "${DIST_DIR}/"
        done
        rmdir "${DIST_DIR}/dist" 2>/dev/null || true
      fi
      rm -rf "$tmpd"
      if [[ -f "${DIST_DIR}/easy-waf-api" ]]; then
        log "Downloaded and verified release v${ver} → $DIST_DIR"
        return 0
      fi
    fi
    rm -rf "$tmpd"
    log "No verified release v${ver} — building from source..."
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
  if [[ -f "${REPO_ROOT}/scripts/diagnostics.sh" ]]; then
    install -m 0755 "${REPO_ROOT}/scripts/diagnostics.sh" "/usr/sbin/easy-waf-diagnostics"
    log "Installed /usr/sbin/easy-waf-diagnostics (support bundle — run as root, see docs/DIAGNOSTICS.md)"
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

GitHub Release tarball (see .github/workflows/release.yml): nested dist/<binaries> is flattened into repo/dist/ automatically. Manual path: EASY_WAF_DIST_DIR must contain easy-waf-api at top level:
  sudo EASY_WAF_DIST_DIR=/path/to/dist bash $REPO_ROOT/scripts/install.sh

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
  for u in easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service easy-wafd.service; do
    if [[ -f "${SYSTEMD_SRC}/${u}" ]]; then
      install -m 0644 "${SYSTEMD_SRC}/${u}" "/etc/systemd/system/${u}"
      log "Installed /etc/systemd/system/${u}"
    fi
  done
  systemctl daemon-reload
  log "Run: systemctl enable --now easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service"
}

# LEGACY — use cleanup_legacy_fail2ban_access + easy-waf-hostd. Kept for fix-fail2ban-api-access.sh.
install_fail2ban_api_access() {
  # shellcheck source=lib/fail2ban-access.sh
  source "${SCRIPT_DIR}/lib/fail2ban-access.sh"
  easy_waf_install_fail2ban_api_access "$REPO_ROOT"
}

# LEGACY — not installed by install.sh; fail2ban goes through easy-waf-hostd.
install_fail2ban_sudoers() {
  if ! id easy-waf &>/dev/null; then
    return 0
  fi
  if ! command -v fail2ban-client &>/dev/null; then
    return 0
  fi
  local f="/etc/sudoers.d/easy-waf-fail2ban"
  cat >"$f" <<'EOF'
# Easy Home WAF — management API may read status and unban via fail2ban-client.
Cmnd_Alias EASY_WAF_FAIL2BAN = /usr/bin/fail2ban-client status, /usr/bin/fail2ban-client status *, /usr/bin/fail2ban-client set * unbanip *
easy-waf ALL=(root) NOPASSWD: EASY_WAF_FAIL2BAN
EOF
  chmod 0440 "$f"
  if command -v visudo &>/dev/null; then
    if ! visudo -cf "$f" 2>/dev/null; then
      rm -f "$f"
      log "WARNING: invalid easy-waf-fail2ban sudoers — skipped"
      return 0
    fi
  fi
  log "Installed $f (fail2ban status/unban for easy-waf user)"
}

install_polkit_rules() {
  if command -v pkaction >/dev/null 2>&1 || [[ -d /etc/polkit-1/rules.d ]]; then
    local polkit_src="${REPO_ROOT}/packaging/polkit"
    if [[ -d "$polkit_src" ]]; then
      mkdir -p /etc/polkit-1/rules.d
      if [[ -f "${polkit_src}/99-easy-waf-haproxy.rules" ]]; then
        install -m 0644 "${polkit_src}/99-easy-waf-haproxy.rules" "/etc/polkit-1/rules.d/"
        log "Installed /etc/polkit-1/rules.d/99-easy-waf-haproxy.rules"
      fi
    fi
  fi
}

cleanup_legacy_host_privilege() {
  rm -f /etc/sudoers.d/easy-waf-host
  rm -f /usr/lib/easy-waf/host-privileged.sh
  rm -f /etc/polkit-1/rules.d/99-easy-waf-host.rules
  log "Removed legacy host sudoers/helper/polkit (if present)"
}

# Fail2ban API access via easy-waf-hostd; remove group/socket/sudoers drop-ins from older installs.
cleanup_legacy_fail2ban_access() {
  rm -f /etc/sudoers.d/easy-waf-fail2ban
  rm -f /etc/systemd/system/fail2ban.service.d/easy-waf-socket.conf
  rm -f /etc/systemd/system/easy-waf-api.service.d/fail2ban.conf
  if command -v systemctl &>/dev/null; then
    systemctl daemon-reload 2>/dev/null || true
  fi
  log "Removed legacy fail2ban socket/sudoers access (if present); use easy-waf-hostd"
}

install_hostd_binary() {
  if [[ -f "${DIST_DIR}/easy-waf-hostd" ]]; then
    install -m 0755 "${DIST_DIR}/easy-waf-hostd" /usr/sbin/easy-waf-hostd
    log "Installed /usr/sbin/easy-waf-hostd"
  else
    log "WARNING: ${DIST_DIR}/easy-waf-hostd missing — build with: make build"
  fi
}


selinux_restore() {
  # Ubuntu uses AppArmor, not SELinux. No action needed.
  # Stock AppArmor profile for HAProxy is sufficient.
  :
}

# HAProxy ↔ easy-waf: /run/haproxy, systemd drop-in (when haproxy binary exists).
easy_waf_integrate_haproxy_edge() {
  if [[ "${EASY_WAF_SKIP_SYSTEMD:-0}" == "1" ]]; then
    return 0
  fi
  if ! command -v haproxy &>/dev/null; then
    return 0
  fi
  ensure_haproxy_run_dir
  if [[ "${EASY_WAF_SKIP_HAPROXY_SYSTEMD_DROPIN:-0}" == "1" ]]; then
    log "Skipping HAProxy drop-in (EASY_WAF_SKIP_HAPROXY_SYSTEMD_DROPIN=1)"
    return 0
  fi
  if [[ -f "${SCRIPT_DIR}/fix-haproxy-easy-waf-dropin.sh" ]]; then
    sed -i 's/\r$//' "${SCRIPT_DIR}/fix-haproxy-easy-waf-dropin.sh" 2>/dev/null || true
    if ! EASY_WAF_STATE_DIR="$STATE_DIR" EASY_WAF_REPO_ROOT="$REPO_ROOT" bash "${SCRIPT_DIR}/fix-haproxy-easy-waf-dropin.sh"; then
      log "WARNING: HAProxy drop-in script had issues — sudo EASY_WAF_REPO_ROOT=$REPO_ROOT bash ${SCRIPT_DIR}/fix-haproxy-easy-waf-dropin.sh"
    fi
  else
    log "WARNING: missing ${SCRIPT_DIR}/fix-haproxy-easy-waf-dropin.sh"
  fi
}

install_os_packages() {
  if [[ "${EASY_WAF_INSTALL_OS_PACKAGES:-1}" != "1" ]]; then
    log "Skipping OS packages (EASY_WAF_INSTALL_OS_PACKAGES=0)"
    return 0
  fi

  case "${EASY_WAF_PKG_MGR:-}" in
    apt)
      easy_waf_apt_get_update
      log "Installing base OS packages via apt (Ubuntu)..."
      local -a base_pkgs=(
        haproxy
        nftables
        ca-certificates
        curl
        iproute2
        netplan.io
        iputils-ping
        traceroute
        iputils-tracepath
        systemd
        policykit-1
        sudo
      )
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${base_pkgs[@]}" \
        || die "apt install failed (haproxy/nftables/base packages)"

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
        log "PostgreSQL enabled — ensure /etc/easy-waf/easy-waf.env DATABASE_URL matches your cluster"
      else
        log "PostgreSQL server not installed (EASY_WAF_INSTALL_POSTGRES=0) — set DATABASE_URL to your external instance"
      fi

      systemctl enable nftables 2>/dev/null || true
      systemctl enable haproxy 2>/dev/null || true
      if easy_waf_pkg_installed fail2ban; then
        systemctl enable fail2ban 2>/dev/null || true
        if [[ "${EASY_WAF_FAIL2BAN_AUTO_START:-1}" == "1" ]]; then
          systemctl start fail2ban 2>/dev/null || true
        fi
      fi
      log "Enabled haproxy, nftables (fail2ban if installed)"
      ;;
    *)
      die "Ubuntu with apt-get required — set EASY_WAF_INSTALL_OS_PACKAGES=0 only if you install deps manually (see docs/DEPLOYMENT.md)"
      ;;
  esac
}

# nftables: management + edge rules (see scripts/lib/nftables-easy-waf.sh).
configure_nftables_appliance() {
  if [[ "${EASY_WAF_INSTALL_OS_PACKAGES:-1}" != "1" ]]; then
    return 0
  fi
  local mgmt_lan="${EASY_WAF_NFT_MGMT_LAN:-${EASY_WAF_FIREWALLD_MGMT_LAN:-1}}"
  local mgmt_ports="${EASY_WAF_NFT_MGMT_PORTS:-${EASY_WAF_FIREWALLD_MGMT_PORTS:-8000 8443}}"
  local edge="${EASY_WAF_NFT_EDGE:-${EASY_WAF_FIREWALLD_EDGE:-1}}"
  # shellcheck source=lib/nftables-easy-waf.sh
  source "${SCRIPT_DIR}/lib/nftables-easy-waf.sh"
  easy_waf_nft_configure_appliance "$mgmt_lan" "$mgmt_ports" "$edge" "${EASY_WAF_EXTRA_LAN_CIDR:-}"
}

# HAProxy is the public edge; ensure it is enabled at boot even when OS packages were skipped.
ensure_haproxy_systemd_enabled() {
  if [[ "${EASY_WAF_SKIP_SYSTEMD:-0}" == "1" ]]; then
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  if systemctl enable haproxy.service 2>/dev/null; then
    log "Ensured haproxy.service is enabled at boot (edge load balancer)"
  else
    log "WARNING: systemctl enable haproxy.service failed — install haproxy or enable the unit manually"
  fi
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
  ensure_haproxy_systemd_enabled
  create_user_and_layout
  ensure_haproxy_run_dir
  install_env_file
  if ! easy_waf_install_crowdsec_packages; then
    if [[ "${EASY_WAF_INSTALL_CROWDSEC:-1}" == "1" ]] && [[ "${EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL:-1}" == "1" ]]; then
      exit 1
    fi
  fi
  if ! easy_waf_bootstrap_crowdsec_lapi; then
    exit 1
  fi
  setup_local_postgres_database
  acquire_dist_binaries
  install_binaries
  easy_waf_sync_settings_to_db
  install_systemd_units
  install_polkit_rules
  cleanup_legacy_host_privilege
  install_hostd_binary
  cleanup_legacy_fail2ban_access
  selinux_restore
  easy_waf_integrate_haproxy_edge
  easy_waf_load_nft_env_from_file_if_unset
  configure_nftables_appliance

  # shellcheck source=lib/management-listen.sh
  source "${SCRIPT_DIR}/lib/management-listen.sh"
  easy_waf_fixup_management_listen_addrs "$CFG_DIR/easy-waf.env"

  if [[ "${EASY_WAF_ENABLE_SYSTEMD_UNITS:-1}" == "1" ]] && [[ "${EASY_WAF_SKIP_SYSTEMD:-0}" != "1" ]]; then
    if systemctl enable --now easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service; then
      log "Enabled and started easy-waf-hostd, easy-waf-api, easy-waf-acmed"
    else
      log "WARNING: systemctl enable --now failed — run: sudo systemctl enable --now easy-waf-hostd easy-waf-api easy-waf-acmed"
      log "Then: sudo journalctl -u easy-waf-hostd -u easy-waf-api -u easy-waf-acmed -n 40 --no-pager"
    fi
  else
    log "Services not started (EASY_WAF_ENABLE_SYSTEMD_UNITS=0 or EASY_WAF_SKIP_SYSTEMD=1)"
    log "Run: sudo systemctl enable --now easy-waf-hostd easy-waf-api easy-waf-acmed"
  fi

  if [[ "${EASY_WAF_INSTALL_POSTGRES:-1}" != "1" ]]; then
    log "Using external DB — ensure $CFG_DIR/easy-waf.env DATABASE_URL is correct"
  fi
  easy_waf_post_install_summary
  log "Done. Management UI: use the EASY_WAF_LISTEN_HTTPS address from $CFG_DIR/easy-waf.env; cleartext HTTP is off unless explicitly enabled"
  log "HAProxy edge: tcp 80+443 via nftables (disable with EASY_WAF_NFT_EDGE=0)"
}

# Print appliance health after install (non-fatal; guides operator).
easy_waf_post_install_summary() {
  log "=== Post-install summary ==="
  local u
  for u in easy-waf-hostd easy-waf-api easy-waf-acmed haproxy postgresql nftables; do
    if systemctl list-unit-files "${u}.service" &>/dev/null; then
      log "  ${u}: $(systemctl is-active "${u}.service" 2>/dev/null || echo unknown)"
    fi
  done
  if [[ "${EASY_WAF_INSTALL_CROWDSEC:-1}" == "1" ]]; then
    if command -v cscli &>/dev/null; then
      log "  crowdsec: $(systemctl is-active crowdsec.service 2>/dev/null || echo unknown)"
      log "  crowdsec-spoa: $(systemctl is-active "$(crowdsec_spoa_bouncer_unit)" 2>/dev/null || echo unknown)"
    else
      log "  ERROR: CrowdSec not installed — re-run: sudo bash scripts/install.sh (need packagecloud + apt)"
    fi
  fi
  if command -v fail2ban-client &>/dev/null; then
    log "  fail2ban: $(systemctl is-active fail2ban.service 2>/dev/null || echo unknown)"
  fi
}

main "$@"
