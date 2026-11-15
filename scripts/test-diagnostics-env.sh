#!/usr/bin/env bash
# Exercise the real collector with private probes, no host service or database access.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$SCRIPT_DIR/diagnostics.sh}"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
real_psql="$(type -P psql || true)"
real_tar="$(type -P tar)"
mkdir -p "$ROOT/bin" "$ROOT/state"
export DIAG_TEST_ARGS="$ROOT/psql-args"
export DIAG_TEST_PSQL_MODE=ok
cat >"$ROOT/bin/id" <<'MOCK'
#!/usr/bin/env bash
printf '0\n'
MOCK
cat >"$ROOT/bin/psql" <<'MOCK'
#!/usr/bin/env bash
[[ -z "${DIAG_UNUSED_SECRET+x}" ]] || exit 91
printf '%s\n' "$@" >"$DIAG_TEST_ARGS"
if [[ "$DIAG_TEST_PSQL_MODE" == real ]]; then
  exec "$DIAG_TEST_REAL_PSQL" "$@"
fi
if [[ "$DIAG_TEST_PSQL_MODE" == fail ]]; then
  printf 'fixture-sensitive-sql-stdout\n'
  printf 'fixture-sensitive-sql-stderr\n' >&2
  exit 2
fi
printf 'fixture-revision-output\n'
printf 'fixture-sensitive-sql-warning\n' >&2
MOCK
for probe in hostnamectl free df uptime ss aa-status systemctl journalctl haproxy nft; do
  printf '#!/bin/sh\nexit 0\n' >"$ROOT/bin/$probe"
done
chmod 0700 "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"
export EASY_WAF_ENV_FILE="$ROOT/config.env"
export EASY_WAF_STATE_DIR="$ROOT/state"
unset DIAG_UNUSED_SECRET
marker="$ROOT/executed"
expected="postgres://fixture:literal-\$not_expanded@fixture.invalid/db?sslmode=disable"
printf 'UNUSED=%s\nDIAG_UNUSED_SECRET=fixture-secret\nDATABASE_URL="%s"\n' \
  "\$(touch \"$marker\")" "$expected" >"$EASY_WAF_ENV_FILE"
cat >>"$EASY_WAF_ENV_FILE" <<'ENV'
TOKEN=fixture-exact-token
PASSWORD_HINT=fixture-prefix-password
  CROWDSEC_LAPI_KEY = fixture-spaced-crowdsec
EASY_WAF_JWT_SECRET   =fixture-spaced-jwt
token =fixture-lowercase-token
  DATABASE_URL =host=fixture password=fixture-spaced-dsn
FOO=public-value
# TOKEN=comment-example
ENV
collector_status=0
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1 || collector_status=$?
[[ ! -e "$marker" ]] || { echo 'FAIL: diagnostics executed env file' >&2; exit 1; }
[[ "$collector_status" == 0 ]] || { echo 'FAIL: collector did not finish' >&2; exit 1; }
[[ -f "$DIAG_TEST_ARGS" ]] || { echo 'FAIL: SQL probe did not run or received unrelated secret' >&2; exit 1; }
[[ "$(head -n 1 "$DIAG_TEST_ARGS")" == "$expected" ]] || { echo 'FAIL: DSN not preserved literally' >&2; exit 1; }
tar -tzf "$ROOT/bundle.tar.gz" >"$ROOT/members"
grep -q '/sql/config_revisions.txt$' "$ROOT/members"
masked_member="$(grep '/config/easy-waf.env.masked$' "$ROOT/members")"
tar -xOzf "$ROOT/bundle.tar.gz" "$masked_member" >"$ROOT/masked"
if grep -Eq 'fixture-(exact-token|prefix-password|spaced-crowdsec|spaced-jwt|lowercase-token|spaced-dsn)' "$ROOT/masked"; then
  echo 'FAIL: support archive contains an unmasked secret' >&2; exit 1
fi
for key in TOKEN PASSWORD_HINT CROWDSEC_LAPI_KEY EASY_WAF_JWT_SECRET token DATABASE_URL; do
  grep -qxF "$key=***MASKED***" "$ROOT/masked" || { echo 'FAIL: masked key missing' >&2; exit 1; }
done
grep -qxF 'FOO=public-value' "$ROOT/masked"
grep -qxF '# TOKEN=comment-example' "$ROOT/masked"
sql_member="$(grep '/sql/config_revisions.txt$' "$ROOT/members")"
sql_err_member="$(grep '/sql/config_revisions.err$' "$ROOT/members")"
tar -xOzf "$ROOT/bundle.tar.gz" "$sql_member" >"$ROOT/sql-output"
tar -xOzf "$ROOT/bundle.tar.gz" "$sql_err_member" >"$ROOT/sql-error"
grep -qxF 'fixture-revision-output' "$ROOT/sql-output"
[[ ! -s "$ROOT/sql-error" ]] || { echo 'FAIL: SQL warning retained in support archive' >&2; exit 1; }
export DIAG_TEST_PSQL_MODE=fail
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
tar -tzf "$ROOT/bundle.tar.gz" >"$ROOT/members"
sql_member="$(grep '/sql/config_revisions.txt$' "$ROOT/members")"
sql_err_member="$(grep '/sql/config_revisions.err$' "$ROOT/members")"
tar -xOzf "$ROOT/bundle.tar.gz" "$sql_member" >"$ROOT/sql-output"
tar -xOzf "$ROOT/bundle.tar.gz" "$sql_err_member" >"$ROOT/sql-error"
[[ ! -s "$ROOT/sql-output" ]] || { echo 'FAIL: failed SQL partial output retained' >&2; exit 1; }
grep -qxF 'SQL revision query failed (psql exit 2); inspect the database connection locally.' "$ROOT/sql-error"
if [[ -n "$real_psql" ]]; then
  export DIAG_TEST_PSQL_MODE=real DIAG_TEST_REAL_PSQL="$real_psql"
  printf 'DATABASE_URL=postgresql://fixture:fixture-sensitive-password%%ZZ@fixture.invalid/db\n' >"$EASY_WAF_ENV_FILE"
  bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
  tar -tzf "$ROOT/bundle.tar.gz" >"$ROOT/members"
  sql_err_member="$(grep '/sql/config_revisions.err$' "$ROOT/members")"
  tar -xOzf "$ROOT/bundle.tar.gz" "$sql_err_member" >"$ROOT/sql-error"
  grep -qxF 'SQL revision query failed (psql exit 2); inspect the database connection locally.' "$ROOT/sql-error"
  echo 'OK: real libpq credential error omitted'
fi
export DIAG_TEST_PSQL_MODE=ok
unset DIAG_TEST_REAL_PSQL
fixture="$SCRIPT_DIR/../internal/diagnostics/testdata/environment-multiline"
cp "$fixture.env.example" "$EASY_WAF_ENV_FILE"
unset DATABASE_URL
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
tar -tzf "$ROOT/bundle.tar.gz" >"$ROOT/members"
masked_member="$(grep '/config/easy-waf.env.masked$' "$ROOT/members")"
tar -xOzf "$ROOT/bundle.tar.gz" "$masked_member" >"$ROOT/masked"
if grep -qF 'fixture-sensitive' "$ROOT/masked"; then
  echo 'FAIL: multiline secret appears in support archive' >&2; exit 1
fi
cmp "$fixture.masked.example" "$ROOT/masked" || { echo 'FAIL: multiline secret masking differs' >&2; exit 1; }
export DATABASE_URL='postgres://process-fixture/db'
printf 'DATABASE_URL=\n' >"$EASY_WAF_ENV_FILE"
rm "$DIAG_TEST_ARGS"
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
[[ ! -e "$DIAG_TEST_ARGS" ]] || { echo 'FAIL: empty file DSN used process fallback' >&2; exit 1; }
: >"$EASY_WAF_ENV_FILE"
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
[[ "$(head -n 1 "$DIAG_TEST_ARGS")" == "$DATABASE_URL" ]] || { echo 'FAIL: missing-key process fallback lost' >&2; exit 1; }
# Publishing replaces the chosen pathname, never the inode behind a link.
printf 'private-target\n' >"$ROOT/protected"
cp "$ROOT/protected" "$ROOT/protected.expected"
ln "$ROOT/protected" "$ROOT/hardlink.tar.gz"
bash "$COLLECTOR" "$ROOT/hardlink.tar.gz" >"$ROOT/output" 2>&1
cmp -s "$ROOT/protected" "$ROOT/protected.expected" || { echo 'FAIL: archive overwrote hardlink target' >&2; exit 1; }
tar -tzf "$ROOT/hardlink.tar.gz" >/dev/null
ln -s "$ROOT/protected" "$ROOT/symlink.tar.gz"
if [[ -L "$ROOT/symlink.tar.gz" ]]; then
  bash "$COLLECTOR" "$ROOT/symlink.tar.gz" >"$ROOT/output" 2>&1
  [[ ! -L "$ROOT/symlink.tar.gz" ]] || { echo 'FAIL: archive followed output symlink' >&2; exit 1; }
  cmp -s "$ROOT/protected" "$ROOT/protected.expected" || { echo 'FAIL: archive changed symlink target' >&2; exit 1; }
  tar -tzf "$ROOT/symlink.tar.gz" >/dev/null
  ln -s "$ROOT/absent-target" "$ROOT/dangling.tar.gz"
  bash "$COLLECTOR" "$ROOT/dangling.tar.gz" >"$ROOT/output" 2>&1
  [[ ! -e "$ROOT/absent-target" && ! -L "$ROOT/dangling.tar.gz" ]] || { echo 'FAIL: archive followed dangling output symlink' >&2; exit 1; }
  tar -tzf "$ROOT/dangling.tar.gz" >/dev/null
else
  echo 'SKIP: filesystem does not create symlinks'
fi
mkdir "$ROOT/output-directory"
if bash "$COLLECTOR" "$ROOT/output-directory" >"$ROOT/output" 2>&1; then
  echo 'FAIL: archive accepted a directory as output' >&2; exit 1
fi
[[ -z "$(find "$ROOT/output-directory" -mindepth 1 -print)" ]] || { echo 'FAIL: archive moved inside output directory' >&2; exit 1; }
export DIAG_TEST_REAL_TAR="$real_tar" DIAG_TEST_TAR_MODE=fail
cat >"$ROOT/bin/tar" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == -czf ]]; then
  if [[ "$DIAG_TEST_TAR_MODE" == fail ]]; then
    printf 'incomplete-archive' >"$2"
    exit 23
  fi
  # NTFS Git Bash does not enforce POSIX creation modes. Check them on Linux.
  if [[ "$(uname -s)" == Linux ]]; then
    [[ -f "$2" && "$(stat -c %a "$2")" == 600 ]] || exit 24
    [[ "$(stat -c %a "$(dirname "$2")")" == 700 ]] || exit 25
  fi
fi
exec "$DIAG_TEST_REAL_TAR" "$@"
MOCK
chmod 0700 "$ROOT/bin/tar"
printf 'previous-archive\n' >"$ROOT/bundle.tar.gz"
if bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1; then
  echo 'FAIL: tar failure reported success' >&2; exit 1
fi
[[ "$(cat "$ROOT/bundle.tar.gz")" == previous-archive ]] || { echo 'FAIL: tar failure damaged previous archive' >&2; exit 1; }
export DIAG_TEST_TAR_MODE=inspect
(umask 000; bash "$COLLECTOR" "$ROOT/new.tar.gz" >"$ROOT/output" 2>&1)
"$real_tar" -tzf "$ROOT/new.tar.gz" >/dev/null
if [[ "$(uname -s)" == Linux ]]; then
  [[ "$(stat -c %a "$ROOT/new.tar.gz")" == 640 ]] || { echo 'FAIL: published archive permissions' >&2; exit 1; }
fi
[[ -z "$(find "$ROOT" -maxdepth 1 -name '.easy-waf-diag.*' -print)" ]] || { echo 'FAIL: publication staging left behind' >&2; exit 1; }
echo 'OK: diagnostics env stays data; archive publication preserves targets'
