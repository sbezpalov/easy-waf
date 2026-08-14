#!/usr/bin/env bash
# Support diagnostics bundle (no private keys / PEM bodies; secrets in easy-waf.env are masked).
# Run as root: sudo bash scripts/diagnostics.sh [output.tar.gz]
#
# Env: EASY_WAF_STATE_DIR (default /var/lib/easy-waf)
#      EASY_WAF_ENV_FILE  (default /etc/easy-waf/easy-waf.env)
#
# Default output: /tmp/easy-waf-diag-YYYYMMDD-HHMMSS.tar.gz

set -euo pipefail

STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
ENV_FILE="${EASY_WAF_ENV_FILE:-/etc/easy-waf/easy-waf.env}"
STAMP="$(date +%Y%m%d-%H%M%S)"
DEFAULT_OUT="/tmp/easy-waf-diag-${STAMP}.tar.gz"
OUT="${1:-$DEFAULT_OUT}"
if [[ "$OUT" != /* ]]; then
  OUT="$(pwd)/${OUT#./}"
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root: sudo bash $0 $*" >&2
  exit 1
fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-diag.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

TOP="easy-waf-diag-${STAMP}"
ROOT="$WORKDIR/$TOP"
mkdir -p "$ROOT"/{system,systemctl,logs,config,validation,sql,firewall}

{
  echo "easy-waf-diagnostics-format v1"
  echo "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "hostname=$(hostname -f 2>/dev/null || hostname)"
  echo "version=${EASY_WAF_VERSION:-unknown}"
  echo "bundle_source=scripts/diagnostics.sh"
} >"$ROOT/MANIFEST.txt"

# --- (a) System ---
uname -a >"$ROOT/system/uname.txt" 2>&1 || true
if [[ -f /etc/os-release ]]; then
  cat /etc/os-release >"$ROOT/system/os-release.txt"
else
  echo "(missing /etc/os-release)" >"$ROOT/system/os-release.txt"
fi
hostnamectl >"$ROOT/system/hostnamectl.txt" 2>&1 || true
free -m >"$ROOT/system/free-m.txt" 2>&1 || true
df -h >"$ROOT/system/df-h.txt" 2>&1 || true
uptime >"$ROOT/system/uptime.txt" 2>&1 || true
ss -tlnp >"$ROOT/system/ss-tlnp.txt" 2>&1 || true
aa-status >"$ROOT/system/aa-status.txt" 2>&1 || true
aa-status --enabled 2>/dev/null >"$ROOT/system/aa-status-enabled.txt" 2>&1 || true

# --- (b) systemd ---
units=(easy-waf-api easy-waf-acmed haproxy crowdsec fail2ban nftables)
for u in "${units[@]}"; do
  safe="${u//\//-}"
  systemctl status "$u" --no-pager -l >"$ROOT/systemctl/status-${safe}.txt" 2>&1 || true
  {
    echo -n "is-enabled: "
    systemctl is-enabled "$u" 2>&1 || true
  } >"$ROOT/systemctl/is-enabled-${safe}.txt" 2>&1 || true
done

# --- (c) journals (last 500 lines, last 24h) ---
jlog() {
  local unit="$1" dst="$2"
  journalctl -u "$unit" --since "24 hours ago" -n 500 --no-pager >"$dst" 2>&1 || true
}
jlog easy-waf-api "$ROOT/logs/journal-easy-waf-api.txt"
jlog easy-waf-acmed "$ROOT/logs/journal-easy-waf-acmed.txt"
jlog haproxy "$ROOT/logs/journal-haproxy.txt"

# --- (d) Config (masked env) ---
mask_env_to() {
  local src="$1" dst="$2"
  if [[ ! -f "$src" ]]; then
    echo "(missing $src)" >"$dst"
    return
  fi
  # Mask DB password in postgres(ql)://user:pass@host URLs; full-line mask for known secrets.
  sed -E \
    -e 's#^(DATABASE_URL=postgres(ql)?://[^:]+:)[^@]+(@.*)$#\1***MASKED***\2#' \
    -e 's/^(CROWDSEC_LAPI_KEY=).*/\1***MASKED***/' \
    -e 's/^(EASY_WAF_JWT_SECRET=).*/\1***MASKED***/' \
    -e 's/^(EASY_WAF_ADMIN_TOKEN=).*/\1***MASKED***/' \
    -e 's/^([A-Za-z_][A-Za-z0-9_]*(PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE_KEY|API_KEY|ACCESS_KEY|LICENSE_KEY)[A-Za-z0-9_]*=).*/\1***MASKED***/I' \
    "$src" >"$dst"
}

mask_env_to "$ENV_FILE" "$ROOT/config/easy-waf.env.masked"

HAPROXY_CFG="${STATE}/haproxy/haproxy.cfg"
if [[ -f "$HAPROXY_CFG" ]]; then
  cp -a "$HAPROXY_CFG" "$ROOT/config/haproxy.cfg"
else
  echo "(missing $HAPROXY_CFG)" >"$ROOT/config/haproxy.cfg"
fi

CRT_LIST="${STATE}/haproxy/crt-list.txt"
if [[ -f "$CRT_LIST" ]]; then
  : >"$ROOT/config/crt-list-filenames.txt"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//[$'\t\r\n']}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    basename "$line" >>"$ROOT/config/crt-list-filenames.txt"
  done <"$CRT_LIST"
else
  echo "(missing $CRT_LIST)" >"$ROOT/config/crt-list-filenames.txt"
fi

# --- (e) HAProxy validation ---
if command -v haproxy &>/dev/null; then
  haproxy -vv >"$ROOT/validation/haproxy-vv.txt" 2>&1 || true
  haproxy -c -f "$HAPROXY_CFG" >"$ROOT/validation/haproxy-check.txt" 2>&1 || true
else
  echo "haproxy binary not in PATH" >"$ROOT/validation/haproxy-vv.txt"
  echo "haproxy binary not in PATH" >"$ROOT/validation/haproxy-check.txt"
fi

# --- (f) SQL via psql ---
if command -v psql &>/dev/null && [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE" || true
  set +a
  if [[ -n "${DATABASE_URL:-}" ]]; then
    psql "$DATABASE_URL" -X -c "SELECT id, haproxy_sha256 AS sha256, at AS created_at FROM config_revisions ORDER BY id DESC LIMIT 5" \
      >"$ROOT/sql/config_revisions.txt" 2>"$ROOT/sql/config_revisions.err" || true
  else
    echo "DATABASE_URL not set after sourcing $ENV_FILE" >"$ROOT/sql/config_revisions.err"
  fi
else
  echo "psql not installed or env file missing" >"$ROOT/sql/config_revisions.err"
fi

# --- (g) Host firewall (nftables) ---
if command -v nft &>/dev/null; then
  nft list ruleset >"$ROOT/firewall/nft-ruleset.txt" 2>&1 || true
else
  echo "nft not in PATH" >"$ROOT/firewall/nft-ruleset.txt"
fi
if [[ -f /etc/nftables/easy-waf.nft ]]; then
  cp -a /etc/nftables/easy-waf.nft "$ROOT/firewall/easy-waf.nft"
fi

mkdir -p "$(dirname "$OUT")"
tar -czf "$OUT" -C "$WORKDIR" "$TOP"
chmod 0640 "$OUT" 2>/dev/null || true

SIZE="$(du -h "$OUT" | awk '{print $1}')"
echo "[easy-waf-diagnostics] wrote $OUT (size $SIZE)"
