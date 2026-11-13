#!/usr/bin/env bash
# Download GeoLite2-Country.mmdb from MaxMind (requires MAXMIND_LICENSE_KEY).
# Install atomically to EASY_WAF_GEOIP_DIR (default: /var/lib/easy-waf/geoip).
# Running processes notice the replacement on their next settings refresh/render/apply;
# EASY_WAF_RESTART_API=1 restarts it immediately without storing panel credentials.
#
# Cron example (Wednesday 03:00):
#   0 3 * * 3 /opt/easy-waf/scripts/update-geoip-db.sh 2>&1 | /usr/bin/logger -t easy-waf-geoip-update
#
# Environment:
#   MAXMIND_LICENSE_KEY   (required) from https://www.maxmind.com/en/accounts/current/license-key
#   EASY_WAF_GEOIP_DIR    destination directory (default /var/lib/easy-waf/geoip)
#   EASY_WAF_RESTART_API  set to 1/true/yes/on to restart an active local API service

set -euo pipefail

KEY="${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY is required}"
DEST="${EASY_WAF_GEOIP_DIR:-/var/lib/easy-waf/geoip}"
RESTART_API="${EASY_WAF_RESTART_API:-0}"
if [[ ! "$KEY" =~ ^[A-Za-z0-9_-]{8,128}$ ]]; then
  echo "[update-geoip-db] ERROR: MAXMIND_LICENSE_KEY has an unexpected format" >&2
  exit 2
fi
case "${RESTART_API,,}" in
  1|true|yes|on) RESTART_ENABLED=1 ;;
  0|false|no|off|'') RESTART_ENABLED=0 ;;
  *)
    echo "[update-geoip-db] ERROR: EASY_WAF_RESTART_API must be a boolean" >&2
    exit 2
    ;;
esac
if [[ "$RESTART_ENABLED" == "1" ]]; then
  [[ "$(id -u)" == "0" ]] || {
    echo "[update-geoip-db] ERROR: EASY_WAF_RESTART_API requires root" >&2
    exit 1
  }
  command -v systemctl &>/dev/null || {
    echo "[update-geoip-db] ERROR: systemctl not found" >&2
    exit 1
  }
fi
if [[ -L "$DEST" ]]; then
  echo "[update-geoip-db] ERROR: destination directory may not be a symlink: $DEST" >&2
  exit 1
fi

TMP="$(mktemp -d)"
INSTALL_TMP=""
cleanup() {
  if [[ -n "$INSTALL_TMP" ]]; then
    rm -f -- "$INSTALL_TMP" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

URL="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${KEY}&suffix=tar.gz"
echo "[update-geoip-db] downloading…"
# The URL carries the license key, so it goes through a config file on stdin
# instead of argv: command lines are readable by any local user via ps//proc.
curl --config - <<CURLRC
url = "${URL}"
output = "${TMP}/GeoLite2-Country.tar.gz"
silent
show-error
fail
location
proto = "=https"
proto-redir = "=https"
CURLRC

ARCHIVE="$TMP/GeoLite2-Country.tar.gz"
MMDB_MEMBER=""
while IFS= read -r member; do
  case "$member" in
    GeoLite2-Country.mmdb|*/GeoLite2-Country.mmdb)
      if [[ -z "$MMDB_MEMBER" ]]; then
        MMDB_MEMBER="$member"
      fi
      ;;
  esac
done < <(tar -tzf "$ARCHIVE")
if [[ -z "$MMDB_MEMBER" ]]; then
  echo "[update-geoip-db] ERROR: GeoLite2-Country.mmdb not found in archive" >&2
  exit 1
fi
MMDB="$TMP/GeoLite2-Country.mmdb"
tar -xOzf "$ARCHIVE" -- "$MMDB_MEMBER" >"$MMDB"
if [[ ! -s "$MMDB" ]] || ! LC_ALL=C grep -aFq 'MaxMind.com' "$MMDB"; then
  echo "[update-geoip-db] ERROR: extracted file is not a recognizable MaxMind database" >&2
  exit 1
fi

# Keep every destination write at easy-waf privilege even when cron invokes the
# script as root. A compromised service account can then redirect only writes it
# could already perform; it cannot turn this updater into a root symlink writer.
if [[ "$(id -u)" == "0" ]]; then
  command -v runuser &>/dev/null || {
    echo "[update-geoip-db] ERROR: runuser is required when running as root" >&2
    exit 1
  }
  id easy-waf &>/dev/null || {
    echo "[update-geoip-db] ERROR: easy-waf service account not found" >&2
    exit 1
  }
  if [[ ! -d "$DEST" ]]; then
    runuser -u easy-waf -- mkdir -p -m 0750 -- "$DEST"
  fi
  [[ -d "$DEST" ]] || {
    echo "[update-geoip-db] ERROR: destination is not a directory: $DEST" >&2
    exit 1
  }
  chown -h easy-waf:easy-waf "$DEST"
  INSTALL_TMP="$(runuser -u easy-waf -- mktemp "${DEST%/}/.GeoLite2-Country.mmdb.XXXXXX")"
  runuser -u easy-waf -- tee "$INSTALL_TMP" <"$MMDB" >/dev/null
  runuser -u easy-waf -- chmod 0644 "$INSTALL_TMP"
  runuser -u easy-waf -- mv -f -- "$INSTALL_TMP" "$DEST/GeoLite2-Country.mmdb"
else
  # Parent modes follow the caller's umask; only the GeoIP leaf gets 0750.
  # shellcheck disable=SC2174
  mkdir -p -m 0750 -- "$DEST"
  [[ -d "$DEST" && -w "$DEST" ]] || {
    echo "[update-geoip-db] ERROR: destination is not writable: $DEST" >&2
    exit 1
  }
  INSTALL_TMP="$(mktemp "${DEST%/}/.GeoLite2-Country.mmdb.XXXXXX")"
  install -m 0644 "$MMDB" "$INSTALL_TMP"
  mv -f -- "$INSTALL_TMP" "$DEST/GeoLite2-Country.mmdb"
fi
INSTALL_TMP=""
echo "[update-geoip-db] installed → $DEST/GeoLite2-Country.mmdb"

if [[ "$RESTART_ENABLED" == "1" ]]; then
  if systemctl is-active --quiet easy-waf-api.service; then
    systemctl restart easy-waf-api.service
    echo "[update-geoip-db] restarted easy-waf-api.service"
  else
    echo "[update-geoip-db] API service is not active; the new database will be used on its next start"
  fi
else
  echo "[update-geoip-db] running processes detect the replacement on their next settings refresh/apply"
  echo "[update-geoip-db] set EASY_WAF_RESTART_API=1 for an immediate local API restart"
fi
