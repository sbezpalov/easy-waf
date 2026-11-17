#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf -- "$ROOT"' EXIT
mkdir "$ROOT/bin"
export TEST_PSQL_ARGS="$ROOT/psql-args" TEST_PSQL_STDIN="$ROOT/psql-stdin"
new_password=0123456789abcdef0123456789abcdef0123456789abcdef
export TEST_NEW_PASSWORD="$new_password"
cat >"$ROOT/bin/openssl" <<'MOCK'
#!/usr/bin/env bash
[[ "$*" == 'rand -hex 24' ]] || exit 2
printf '%s\n' "$TEST_NEW_PASSWORD"
MOCK
cat >"$ROOT/bin/sudo" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$@" >"$TEST_PSQL_ARGS"
[[ "$*" == '-u postgres psql -X -w -v ON_ERROR_STOP=1 -f -' ]] || exit 2
cat >"$TEST_PSQL_STDIN"
exit "${TEST_PSQL_EXIT:-0}"
MOCK
cat >"$ROOT/bin/psql" <<'MOCK'
#!/bin/sh
exit 2
MOCK
chmod +x "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"

# shellcheck source=lib/env-file.sh
source "$SCRIPT_DIR/lib/env-file.sh"
# shellcheck source=lib/db-password.sh
source "$SCRIPT_DIR/lib/db-password.sh"
flock() { [[ "$1" == -n && "${TEST_LOCK_EXIT:-0}" == 0 ]]; }
config="$ROOT/easy-waf.env"
printf 'DATABASE_URL=postgres://easywaf:secret@127.0.0.1/easywaf?sslmode=disable\nUNRELATED=same\n' >"$config"
easy_waf_maybe_rotate_weak_db_password "$config" >"$ROOT/rotation.log"
if grep -qF "$new_password" "$TEST_PSQL_ARGS"; then
  echo 'FAIL: generated password appeared in PostgreSQL command arguments' >&2
  exit 1
fi
grep -qxF "ALTER USER easywaf WITH PASSWORD '$new_password';" "$TEST_PSQL_STDIN"
grep -qxF "DATABASE_URL=postgres://easywaf:$new_password@127.0.0.1/easywaf?sslmode=disable" "$config"
grep -qxF 'UNRELATED=same' "$config"
if grep -qF "$new_password" "$ROOT/rotation.log"; then
  echo 'FAIL: generated password appeared in the installer log' >&2
  exit 1
fi
sed() { return 5; }
case_config="$ROOT/unwritable-result.env"
printf 'DATABASE_URL=postgres://easywaf:secret@127.0.0.1/easywaf\n' >"$case_config"
rm -f "$TEST_PSQL_ARGS"
if easy_waf_maybe_rotate_weak_db_password "$case_config" >"$ROOT/failure.log"; then
  echo 'FAIL: installer continued after the new database config could not be prepared' >&2
  exit 1
fi
[[ ! -e "$TEST_PSQL_ARGS" ]] || { echo 'FAIL: password was changed before staging succeeded' >&2; exit 1; }
unset -f sed

shopt -s nullglob
staged=("$case_config".rotation.*)
[[ "${#staged[@]}" == 0 ]]
grep -qxF 'DATABASE_URL=postgres://easywaf:secret@127.0.0.1/easywaf' "$case_config"
export TEST_LOCK_EXIT=1
if easy_waf_maybe_rotate_weak_db_password "$case_config" >"$ROOT/failure.log" 2>&1; then
  echo 'FAIL: installer continued when the configuration directory was locked' >&2
  exit 1
fi
[[ ! -e "$TEST_PSQL_ARGS" ]]
unset TEST_LOCK_EXIT

check_retained_config() {
  local active="$1" expected_error="$2"
  if easy_waf_maybe_rotate_weak_db_password "$active" >"$ROOT/failure.log" 2>&1; then
    echo 'FAIL: installer returned success after rotation failure' >&2
    exit 1
  fi
  local -a recovery=("$active".rotation.*)
  [[ "${#recovery[@]}" == 1 ]]
  grep -qxF 'DATABASE_URL=postgres://easywaf:secret@127.0.0.1/easywaf' "$active"
  grep -qxF "DATABASE_URL=postgres://easywaf:$new_password@127.0.0.1/easywaf" "${recovery[0]}"
  grep -Fq "$expected_error" "$ROOT/failure.log"
  if grep -Fq "$new_password" "$ROOT/failure.log"; then
    echo 'FAIL: recovery log disclosed the generated password' >&2
    exit 1
  fi
  if [[ "$(uname -s)" == Linux ]]; then
    [[ "$(stat -c '%a' "${recovery[0]}")" == 600 ]]
  fi
}

sql_failure="$ROOT/sql-failure.env"
cp "$case_config" "$sql_failure"
export TEST_PSQL_EXIT=3
check_retained_config "$sql_failure" 'could not confirm the PostgreSQL password change'
unset TEST_PSQL_EXIT
publish_failure="$ROOT/publish-failure.env"
cp "$case_config" "$publish_failure"
mv() { return 5; }
check_retained_config "$publish_failure" 'could not be replaced'
unset -f mv

strong_password="$ROOT/unchanged.env"
printf 'DATABASE_URL=postgres://easywaf:secret@127.0.0.1/easywaf\nDATABASE_URL=postgres://easywaf:provisioned@127.0.0.1/easywaf\n' >"$strong_password"
rm -f "$TEST_PSQL_ARGS"
easy_waf_maybe_rotate_weak_db_password "$strong_password"
[[ ! -e "$TEST_PSQL_ARGS" ]]
echo 'OK: installer stages the complete config before rotating and reports recovery failures'
