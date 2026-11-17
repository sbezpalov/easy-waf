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
MOCK
cat >"$ROOT/bin/psql" <<'MOCK'
#!/bin/sh
exit 2
MOCK
chmod +x "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"

# Force the supported sed fallback without hiding other real tools.
command() {
  if [[ "$*" == '-v python3' ]]; then return 1; fi
  builtin command "$@"
}
# shellcheck source=lib/db-password.sh
source "$SCRIPT_DIR/lib/db-password.sh"
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
echo 'OK: installer rotation sends the generated password to psql on stdin'
