#!/usr/bin/env bash
# Exercise the real collector with private probes, no host service or database access.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR="${1:-$SCRIPT_DIR/diagnostics.sh}"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin" "$ROOT/state"
export DIAG_TEST_ARGS="$ROOT/psql-args"
cat >"$ROOT/bin/id" <<'MOCK'
#!/usr/bin/env bash
printf '0\n'
MOCK
cat >"$ROOT/bin/psql" <<'MOCK'
#!/usr/bin/env bash
[[ -z "${DIAG_UNUSED_SECRET+x}" ]] || exit 91
printf '%s\n' "$@" >"$DIAG_TEST_ARGS"
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
collector_status=0
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1 || collector_status=$?
[[ ! -e "$marker" ]] || { echo 'FAIL: diagnostics executed env file' >&2; exit 1; }
[[ "$collector_status" == 0 ]] || { echo 'FAIL: collector did not finish' >&2; exit 1; }
[[ -f "$DIAG_TEST_ARGS" ]] || { echo 'FAIL: SQL probe did not run or received unrelated secret' >&2; exit 1; }
[[ "$(head -n 1 "$DIAG_TEST_ARGS")" == "$expected" ]] || { echo 'FAIL: DSN not preserved literally' >&2; exit 1; }
tar -tzf "$ROOT/bundle.tar.gz" >"$ROOT/members"
grep -q '/sql/config_revisions.txt$' "$ROOT/members"
export DATABASE_URL='postgres://process-fixture/db'
printf 'DATABASE_URL=\n' >"$EASY_WAF_ENV_FILE"
rm "$DIAG_TEST_ARGS"
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
[[ ! -e "$DIAG_TEST_ARGS" ]] || { echo 'FAIL: empty file DSN used process fallback' >&2; exit 1; }
: >"$EASY_WAF_ENV_FILE"
bash "$COLLECTOR" "$ROOT/bundle.tar.gz" >"$ROOT/output" 2>&1
[[ "$(head -n 1 "$DIAG_TEST_ARGS")" == "$DATABASE_URL" ]] || { echo 'FAIL: missing-key process fallback lost' >&2; exit 1; }
echo 'OK: diagnostics env stays data'
