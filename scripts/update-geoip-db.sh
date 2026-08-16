#!/usr/bin/env bash
# Download GeoLite2-Country.mmdb from MaxMind (requires MAXMIND_LICENSE_KEY).
# Install to EASY_WAF_GEOIP_DIR (default: /var/lib/easy-waf/geoip) and optionally
# call easy-waf-api POST /api/v1/geoip/reload when EASY_WAF_ADMIN_TOKEN is set.
#
# Cron example (Wednesday 03:00):
#   0 3 * * 3 /opt/easy-waf/scripts/update-geoip-db.sh >>/var/log/easy-waf-geoip-update.log 2>&1
#
# Environment:
#   MAXMIND_LICENSE_KEY   (required) from https://www.maxmind.com/en/accounts/current/license-key
#   EASY_WAF_GEOIP_DIR    destination directory (default /var/lib/easy-waf/geoip)
#   EASY_WAF_API_URL      default https://127.0.0.1:8443
#   EASY_WAF_API_CA_CERT  CA/certificate for management HTTPS (default: state management.crt)
#   EASY_WAF_CURL_INSECURE=1 explicitly disable API TLS verification (recovery only)
#   EASY_WAF_ADMIN_TOKEN  optional; if set, triggers MMDB hot-reload in the API process

set -euo pipefail

KEY="${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY is required}"
DEST="${EASY_WAF_GEOIP_DIR:-/var/lib/easy-waf/geoip}"
STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
API="${EASY_WAF_API_URL:-https://127.0.0.1:8443}"
API_CA_CERT="${EASY_WAF_API_CA_CERT:-${STATE}/secrets/management.crt}"
CURL_TLS_ARGS=()
if [[ "$API" == https://* ]]; then
  if [[ "${EASY_WAF_CURL_INSECURE:-0}" == "1" ]]; then
    CURL_TLS_ARGS=(--insecure)
  elif [[ -f "$API_CA_CERT" ]]; then
    CURL_TLS_ARGS=(--cacert "$API_CA_CERT")
  fi
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

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

mkdir -p "$TMP/ex"
tar -xzf "$TMP/GeoLite2-Country.tar.gz" -C "$TMP/ex"
MMDB="$(find "$TMP/ex" -name 'GeoLite2-Country.mmdb' -type f | head -1)"
if [[ -z "$MMDB" ]]; then
  echo "[update-geoip-db] ERROR: GeoLite2-Country.mmdb not found in archive" >&2
  exit 1
fi

mkdir -p "$DEST"
install -m 0644 "$MMDB" "$DEST/GeoLite2-Country.mmdb"
echo "[update-geoip-db] installed → $DEST/GeoLite2-Country.mmdb"

if [[ -n "${EASY_WAF_ADMIN_TOKEN:-}" ]]; then
  echo "[update-geoip-db] POST $API/api/v1/geoip/reload"
  # Same reason as above: the bearer token must not appear in the command line.
  curl "${CURL_TLS_ARGS[@]}" --config - <<CURLRC || {
url = "${API%/}/api/v1/geoip/reload"
request = "POST"
header = "Authorization: Bearer ${EASY_WAF_ADMIN_TOKEN}"
header = "Content-Type: application/json"
header = "X-Requested-With: XMLHttpRequest"
data = "{\"mmdb_path\":\"${DEST}/GeoLite2-Country.mmdb\"}"
silent
show-error
fail
CURLRC
    echo "[update-geoip-db] WARNING: reload request failed (API down or token invalid?)" >&2
  }
else
  echo "[update-geoip-db] skip API reload (set EASY_WAF_ADMIN_TOKEN to enable)"
fi
