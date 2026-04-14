#!/usr/bin/env bash
# Insert pg_hba.conf rules so easy-waf (TCP 127.0.0.1 + password in DATABASE_URL) does not hit "ident" (FATAL: Ident authentication failed).
# Idempotent. Run as root after PostgreSQL is up. Reloads postgresql.

easy_waf_insert_pg_hba_for_easywaf() {
  local pgdata="${1:-}"
  if [[ -z "$pgdata" ]]; then
    pgdata="$(sudo -u postgres psql -tAc 'SHOW data_directory;' 2>/dev/null | tr -d '[:space:]')"
  fi
  [[ -n "$pgdata" && -f "${pgdata}/pg_hba.conf" ]] || pgdata="/var/lib/pgsql/data"
  local hba="${pgdata}/pg_hba.conf"
  [[ -f "$hba" ]] || {
    echo "[easy-waf-pg] WARNING: no $hba - skip pg_hba tweak" >&2
    return 0
  }

  if grep -qF "# BEGIN easy-waf" "$hba" 2>/dev/null; then
    return 0
  fi

  local block='# BEGIN easy-waf (password auth for DATABASE_URL over TCP localhost; before generic host ... ident)
host    easywaf    easywaf    127.0.0.1/32    scram-sha-256
host    easywaf    easywaf    ::1/128         scram-sha-256
# END easy-waf'

  local n
  n="$(awk '/^(local|host|hostssl|hostnossl)[[:space:]]/{print NR; exit}' "$hba" || true)"
  local tmp
  tmp="$(mktemp)"
  if [[ -z "$n" ]]; then
    cat "$hba" >"$tmp"
    printf '\n%s\n' "$block" >>"$tmp"
  else
    head -n "$((n - 1))" "$hba" >"$tmp"
    printf '%s\n' "$block" >>"$tmp"
    tail -n "+${n}" "$hba" >>"$tmp"
  fi
  install -m 0600 "$tmp" "$hba"
  rm -f "$tmp"
  chown postgres:postgres "$hba" 2>/dev/null || true

  if systemctl is-active --quiet postgresql 2>/dev/null; then
    systemctl reload postgresql 2>/dev/null || systemctl restart postgresql 2>/dev/null || true
  fi
  if declare -F log &>/dev/null; then
    log "PostgreSQL pg_hba: scram-sha-256 for easywaf on 127.0.0.1 (::1) - reloaded"
  else
    echo "[easy-waf-pg] scram-sha-256 for easywaf@127.0.0.1 in $hba (postgresql reloaded)" >&2
  fi
}

# Standalone: sudo bash scripts/lib/pg-hba-easywaf.sh
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  [[ "$(id -u)" -eq 0 ]] || {
    echo "Run as root: sudo bash $0" >&2
    exit 1
  }
  easy_waf_insert_pg_hba_for_easywaf ""
fi
