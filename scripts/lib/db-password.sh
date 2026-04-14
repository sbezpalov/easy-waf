#!/usr/bin/env bash
# Rotate weak default PostgreSQL passwords in DATABASE_URL (local appliance).
# Sourced by install-interactive.sh when PostgreSQL was installed via the installer.

log_dbpw() { echo "[easy-waf-db] $*"; }

# If DATABASE_URL still uses known-weak passwords for user easywaf, set a strong random password and ALTER USER.
easy_waf_maybe_rotate_weak_db_password() {
  local env_file="${1:-}"
  [[ -n "$env_file" && -f "$env_file" ]] || return 0
  grep -qE '^DATABASE_URL=postgres://easywaf:(secret|easywaf)@' "$env_file" || return 0

  command -v openssl &>/dev/null || {
    log_dbpw "openssl not found; skip DB password rotation"
    return 0
  }
  local newpw
  newpw="$(openssl rand -hex 24)"

  if command -v psql &>/dev/null && command -v sudo &>/dev/null; then
    if sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER USER easywaf WITH PASSWORD '${newpw}';" 2>/dev/null; then
      :
    else
      log_dbpw "ALTER USER failed — change postgres password manually and update DATABASE_URL"
      return 0
    fi
  else
    log_dbpw "sudo/psql not available; update DATABASE_URL with a strong password manually"
    return 0
  fi

  if command -v python3 &>/dev/null; then
    EASY_WAF_NEW_DB_PW="$newpw" python3 - "$env_file" <<'PY'
import os, re, sys
path = sys.argv[1]
pw = os.environ["EASY_WAF_NEW_DB_PW"]
text = open(path, encoding="utf-8").read()

# Callable repl avoids re.sub interpreting digits in pw as \10, \12, … (invalid group refs).
def repl(m):
    return m.group(1) + pw + m.group(3)

text2 = re.sub(
    r"(^DATABASE_URL=postgres://easywaf:)([^@]+)(@)",
    repl,
    text,
    count=1,
    flags=re.MULTILINE,
)
open(path, "w", encoding="utf-8").write(text2)
PY
    log_dbpw "rotated weak default password for role easywaf in $env_file"
  else
    log_dbpw "python3 not found — set DATABASE_URL password manually to: $newpw"
  fi
}
