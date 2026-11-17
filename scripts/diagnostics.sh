#!/usr/bin/env bash
# Support diagnostics bundle (no private keys / PEM bodies; secrets in easy-waf.env are masked).
# Run as root: sudo bash scripts/diagnostics.sh [output.tar.gz]
#
# Env: EASY_WAF_STATE_DIR (default /var/lib/easy-waf)
#      EASY_WAF_ENV_FILE  (default /etc/easy-waf/easy-waf.env)
#
# Default output: /tmp/easy-waf-diag-YYYYMMDD-HHMMSS.tar.gz

set -euo pipefail
umask 077

# Resolve the installed operator symlink, as backup.sh does.
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh"

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
OUTPUT_WORKDIR=""
cleanup() {
  rm -rf "$WORKDIR"
  if [[ -n "$OUTPUT_WORKDIR" ]]; then
    rm -rf "$OUTPUT_WORKDIR"
  fi
}
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
# easy-waf-hostd is in this list because every privileged operation goes through
# the broker: a bundle taken after a failed host update or firewall apply used to
# be missing the one unit that could explain it.
units=(easy-waf-api easy-waf-acmed easy-waf-hostd haproxy crowdsec fail2ban nftables)
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
jlog easy-waf-hostd "$ROOT/logs/journal-easy-waf-hostd.txt"
jlog haproxy "$ROOT/logs/journal-haproxy.txt"

# --- (d) Config (masked env) ---
mask_env_to() {
  local src="$1" dst="$2"
  if [[ ! -f "$src" ]]; then
    echo "(missing $src)" >"$dst"
    return
  fi
  # Match the API masker: inspect the trimmed key, including exact/prefix
  # markers and whitespace around assignments. Mask the complete DSN too.
  awk '
    # State follows value boundaries only while redacting a sensitive entry.
    # 0=start, 1=unquoted, 2=single quote, 3=double quote, 4/5=escapes.
    function continues(value, i, c) {
      for (i = 1; i <= length(value); i++) {
        c = substr(value, i, 1)
        if (mode == 0) {
          if (c == "\047") mode = 2
          else if (c == "\"") mode = 3
          else if (c == "\\") mode = 4
          else if (c != " " && c != "\t" && c != "\r") mode = 1
        } else if (mode == 1) {
          if (c == "\\") mode = 4
        } else if (mode == 2) {
          if (c == "\047") mode = 0
        } else if (mode == 3) {
          if (c == "\\") mode = 5
          else if (c == "\"") mode = 0
        } else if (mode == 4) mode = 1
        else if (mode == 5) mode = 3
      }
      if (mode == 4) { mode = 1; return 1 }
      if (mode == 5) { mode = 3; return 1 }
      return mode == 2 || mode == 3
    }
    continuing { continuing = continues($0); next }
    /^[[:space:]]*[#;]/ { print; next }
    {
      pos = index($0, "=")
      if (!pos) { print; next }
      key = substr($0, 1, pos - 1)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      upper = toupper(key)
      if (key == "DATABASE_URL" || upper ~ /PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE_KEY|API_KEY|ACCESS_KEY|LICENSE_KEY/) {
        print key "=***MASKED***"
        mode = 0
        continuing = continues(substr($0, pos + 1))
      } else
        print
    }
  ' "$src" >"$dst"
}

mask_haproxy_stream() {
  # Mask the full forward-auth target; query parameters commonly carry tokens.
  # The second expression fails closed if a generated directive is malformed.
  sed -E \
    -e 's#(lua\.easywaf_auth[[:space:]]+")[^"]*"#\1***MASKED***"#g' \
    -e 's#(lua\.easywaf_auth[[:space:]]+")[^"]*$#\1***MASKED***#'
}

mask_haproxy_to() {
  local src="$1" dst="$2"
  mask_haproxy_stream <"$src" >"$dst"
}

mask_env_to "$ENV_FILE" "$ROOT/config/easy-waf.env.masked"

HAPROXY_CFG="${STATE}/haproxy/haproxy.cfg"
if [[ -f "$HAPROXY_CFG" ]]; then
  mask_haproxy_to "$HAPROXY_CFG" "$ROOT/config/haproxy.cfg"
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
  haproxy -c -f "$HAPROXY_CFG" 2>&1 | mask_haproxy_stream >"$ROOT/validation/haproxy-check.txt" || true
else
  echo "haproxy binary not in PATH" >"$ROOT/validation/haproxy-vv.txt"
  echo "haproxy binary not in PATH" >"$ROOT/validation/haproxy-check.txt"
fi

# --- (f) SQL via psql ---
if ! command -v psql &>/dev/null || [[ ! -f "$ENV_FILE" ]]; then
  echo "psql not installed or env file missing" >"$ROOT/sql/config_revisions.err"
elif ! command -v python3 &>/dev/null || [[ ! -r "$SCRIPT_DIR/lib/pg-archive.py" ]]; then
  echo "Python 3 or PostgreSQL client helper missing" >"$ROOT/sql/config_revisions.err"
else
  database_url="${DATABASE_URL:-}"
  if grep -q '^DATABASE_URL=' "$ENV_FILE"; then
    database_url="$(easy_waf_read_env_value "$ENV_FILE" DATABASE_URL)" || database_url=""
  elif [[ "$?" != 1 ]]; then
    echo "Cannot read env file" >"$ROOT/sql/config_revisions.err"
    database_url=""
  fi
  if [[ -n "$database_url" ]]; then
    # libpq errors can echo credential-bearing URI tokens. Do not put raw
    # errors/warnings or failed partial output into a support archive.
    if python3 -I "$SCRIPT_DIR/lib/pg-archive.py" "$WORKDIR" psql -X -w \
      -c "SELECT id, haproxy_sha256 AS sha256, at AS created_at FROM config_revisions ORDER BY id DESC LIMIT 5" \
      <<<"$database_url" \
      >"$ROOT/sql/config_revisions.txt" 2>/dev/null; then
      : >"$ROOT/sql/config_revisions.err"
    else
      sql_status=$?
      : >"$ROOT/sql/config_revisions.txt"
      printf 'SQL revision query failed (exit %s). Inspect the database connection locally.\n' "$sql_status" >"$ROOT/sql/config_revisions.err"
    fi
  else
    echo "DATABASE_URL unavailable or empty" >>"$ROOT/sql/config_revisions.err"
  fi
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
# Build privately on the destination filesystem. Rename replaces the selected
# pathname (including a symlink/hardlink) without truncating its old target.
OUTPUT_WORKDIR="$(mktemp -d "$(dirname "$OUT")/.easy-waf-diag.XXXXXX")"
ARCHIVE="$OUTPUT_WORKDIR/bundle.tar.gz"
: >"$ARCHIVE"
tar -czf "$ARCHIVE" -C "$WORKDIR" "$TOP"
chmod 0640 "$ARCHIVE"
mv -fT -- "$ARCHIVE" "$OUT"

SIZE="$(du -h "$OUT" | awk '{print $1}')"
echo "[easy-waf-diagnostics] wrote $OUT (size $SIZE)"
