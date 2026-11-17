#!/usr/bin/env bash
# Rotate weak default PostgreSQL passwords in DATABASE_URL on a local appliance.
# The caller sources env-file.sh before invoking the rotation.

log_dbpw() { echo "[easy-waf-db] $*"; }

easy_waf_maybe_rotate_weak_db_password() (
  local rotation_env="${1:-}" current newpw staged expected config_dir lock_fd
  [[ -n "$rotation_env" && -f "$rotation_env" ]] || return 0
  current="$(easy_waf_read_env_value "$rotation_env" DATABASE_URL)" || return 1
  [[ "$current" =~ ^postgres://easywaf:(secret|easywaf)@ ]] || return 0

  if ! command -v openssl &>/dev/null || ! command -v sed &>/dev/null ||
     ! command -v psql &>/dev/null || ! command -v sudo &>/dev/null; then
    log_dbpw "openssl, sed, psql and sudo are required to rotate the local password automatically"
    return 0
  fi
  # The installer and backup/restore share a lock on the config directory.
  config_dir="$(dirname -- "$rotation_env")" || return 1
  if ! exec {lock_fd}<"$config_dir" || ! flock -n "$lock_fd"; then
    log_dbpw "ERROR: could not lock the PostgreSQL configuration directory for rotation" >&2
    return 1
  fi
  current="$(easy_waf_read_env_value "$rotation_env" DATABASE_URL)" || return 1
  [[ "$current" =~ ^postgres://easywaf:(secret|easywaf)@ ]] || return 0
  if ! newpw="$(openssl rand -hex 24)" || [[ ! "$newpw" =~ ^[a-f0-9]{48}$ ]]; then
    log_dbpw "ERROR: could not generate the new PostgreSQL password" >&2
    return 1
  fi

  # Stage next to the target, preserving a symlink to an operator-managed file.
  # mktemp creates the full recovery configuration with mode 0600.
  rotation_env="$(readlink -f -- "$rotation_env")" || return 1
  if ! staged="$(mktemp "${rotation_env}.rotation.XXXXXX")"; then
    log_dbpw "ERROR: could not stage the PostgreSQL configuration beside $rotation_env" >&2
    return 1
  fi
  expected="postgres://easywaf:$newpw@${current#*@}"
  if ! printf "s#^(DATABASE_URL=['\"]?postgres://easywaf:)(secret|easywaf)(@)#\\\\1%s\\\\3#\n" "$newpw" |
      sed -E -f - "$rotation_env" >"$staged" ||
     [[ "$(easy_waf_read_env_value "$staged" DATABASE_URL)" != "$expected" ]]; then
    rm -f -- "$staged"
    log_dbpw "ERROR: could not prepare the replacement PostgreSQL configuration" >&2
    return 1
  fi

  if ! printf "ALTER USER easywaf WITH PASSWORD '%s';\n" "$newpw" |
      sudo -u postgres psql -X -w -v ON_ERROR_STOP=1 -f - >/dev/null 2>&1; then
    log_dbpw "ERROR: could not confirm the PostgreSQL password change; recovery configuration retained at $staged" >&2
    return 1
  fi
  if ! mv -fT -- "$staged" "$rotation_env"; then
    log_dbpw "ERROR: PostgreSQL password changed, but $rotation_env could not be replaced; recovery configuration retained at $staged" >&2
    return 1
  fi
  log_dbpw "rotated weak default password for role easywaf in $rotation_env"
)
