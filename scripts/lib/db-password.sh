#!/usr/bin/env bash
# Rotate weak default PostgreSQL passwords in DATABASE_URL (local appliance).
# Sourced by install-interactive.sh when PostgreSQL was installed via the installer.
#
# The generated password is a secret: it is never echoed to stdout (install logs are
# routinely redirected to files or captured by cron). If the env file cannot be
# rewritten, the password is written to a 0600 file and only that path is logged.

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

  # Rotating in PostgreSQL before we know we can persist the new value would leave
  # the appliance with a DATABASE_URL that no longer authenticates.
  if ! command -v python3 &>/dev/null && ! command -v sed &>/dev/null; then
    log_dbpw "neither python3 nor sed available — skip DB password rotation"
    return 0
  fi

  local newpw
  newpw="$(openssl rand -hex 24)" # hex only: safe inside a URL and as a sed replacement

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

  local updated=0
  if command -v python3 &>/dev/null; then
    if EASY_WAF_NEW_DB_PW="$newpw" python3 - "$env_file" <<'PY'
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
    then
      updated=1
    fi
  fi

  if [[ "$updated" -eq 0 ]] && command -v sed &>/dev/null; then
    if sed -i -E "s|(^DATABASE_URL=postgres://easywaf:)[^@]+(@)|\1${newpw}\2|" "$env_file" 2>/dev/null; then
      updated=1
    fi
  fi

  if [[ "$updated" -eq 1 ]]; then
    log_dbpw "rotated weak default password for role easywaf in $env_file"
    return 0
  fi

  # Password already changed in PostgreSQL but the env file was not rewritten:
  # hand it over through a root-only file instead of the log.
  local pwfile="${env_file}.new-db-password"
  if (
    umask 077
    printf '%s\n' "$newpw" >"$pwfile"
  ) 2>/dev/null; then
    log_dbpw "could not rewrite $env_file — new password stored in $pwfile (mode 0600)"
    log_dbpw "put it into DATABASE_URL, then delete $pwfile"
  else
    log_dbpw "could not rewrite $env_file and could not store the new password — reset the easywaf role password manually"
  fi
}
