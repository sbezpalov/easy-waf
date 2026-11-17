#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir -p "$ROOT/scripts/lib" "$ROOT/config"
[[ "$(tail -n 1 "$SOURCE_DIR/install.sh")" == 'main "$@"' ]]
sed '$d' "$SOURCE_DIR/install.sh" >"$ROOT/scripts/install.sh"
cp "$SOURCE_DIR/lib/env-file.sh" "$ROOT/scripts/lib/"
printf 'easy_waf_insert_pg_hba_for_easywaf() { :; }\n' >"$ROOT/scripts/lib/pg-hba-easywaf.sh"
# shellcheck source=/dev/null
source "$ROOT/scripts/install.sh"
export CFG_DIR="$ROOT/config"
export EASY_WAF_INSTALL_POSTGRES=1 EASY_WAF_ROTATE_WEAK_DB_PASSWORD=0
printf 'DATABASE_URL=postgresql://easywaf@127.0.0.1/easywaf\n' >"$CFG_DIR/easy-waf.env"

sudo() {
  [[ "$1" == -u && "$2" == postgres ]] || return 98
  printf '%s\n' "$3" >>"$ROOT/calls"
  case "$3" in
    pg_isready) return "$ready_status" ;;
    createuser|createdb) return "$create_status" ;;
    psql) printf '%s\n' "$catalog"; return "$catalog_status" ;;
    *) return 99 ;;
  esac
}
sleep() { SECONDS=$((SECONDS + 1)); }
fail() { echo "FAIL: $*" >&2; exit 1; }

ready_status=2
create_status=0
catalog='1'
catalog_status=0
: >"$ROOT/calls"
if setup_local_postgres_database >"$ROOT/output" 2>&1; then
  fail 'installer reported success when PostgreSQL never became ready'
fi
if grep -qv '^pg_isready$' "$ROOT/calls"; then
  fail 'installer attempted database writes after the timeout'
fi
grep -Fq 'local PostgreSQL did not become ready' "$ROOT/output" || fail 'timeout lacks diagnostic'

ready_status=0
create_status=1
: >"$ROOT/calls"
setup_local_postgres_database >"$ROOT/output" 2>&1 || fail 'installer rejected valid preexisting role and database'
[[ "$(<"$ROOT/calls")" == $'pg_isready\ncreateuser\ncreatedb\npsql' ]] || fail 'installer did not verify the resulting database'

catalog=''
if setup_local_postgres_database >"$ROOT/output" 2>&1; then
  fail 'installer accepted a role without LOGIN or CONNECT'
fi
grep -Fq 'role easywaf lacks LOGIN or CONNECT' "$ROOT/output" || fail 'catalog check lacks diagnostic'
catalog='1'
catalog_status=2
if setup_local_postgres_database >"$ROOT/output" 2>&1; then
  fail 'installer trusted a failed catalog connection'
fi

mv "$CFG_DIR/easy-waf.env" "$ROOT/saved.env"
: >"$ROOT/calls"
if setup_local_postgres_database >"$ROOT/output" 2>&1; then
  fail 'local provisioning accepted missing configuration'
fi
EASY_WAF_INSTALL_POSTGRES=0 setup_local_postgres_database || fail 'external database mode no longer skips local provisioning'
[[ ! -s "$ROOT/calls" ]] || fail 'unexpected database access without local configuration'
echo 'OK: installer rejects failed local PostgreSQL provisioning and accepts a usable existing database'
