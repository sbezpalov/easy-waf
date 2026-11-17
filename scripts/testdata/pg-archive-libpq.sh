#!/usr/bin/env bash
# Run as an unprivileged user with PostgreSQL 16 binaries and Python 3 installed.
set -euo pipefail
umask 077
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_DUMP="$(command -v pg_dump)"
REAL_RESTORE="$(command -v pg_restore)"
export REAL_DUMP REAL_RESTORE
export PATH="/usr/lib/postgresql/16/bin:$PATH"
work="$(mktemp -d)"
cleanup() {
  pg_ctl -D "$work/data" -m fast -w stop >/dev/null 2>&1 || true
  rm -rf -- "$work"
}
trap cleanup EXIT
mkdir "$work/socket" "$work/bin" "$work/private"
initdb -D "$work/data" -U bootstrap --no-locale --auth-local=trust --auth-host=scram-sha-256 >/dev/null
pg_ctl -D "$work/data" -l "$work/data/server.log" \
  -o "-h 127.0.0.1 -p 55477 -k $work/socket" -w start >/dev/null
export PGHOST="$work/socket" PGPORT=55477 PGUSER=bootstrap
psql -Xw -d postgres -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE ROLE fixture LOGIN PASSWORD 'fixture:special@value';
CREATE DATABASE archive_source OWNER fixture;
CREATE DATABASE archive_target OWNER fixture;
\c archive_source
SET ROLE fixture;
CREATE TABLE evidence (value text);
INSERT INTO evidence VALUES ('fixture');
SQL
cat >"$work/bin/pg_dump" <<'MOCK'
#!/usr/bin/env bash
set -eu
[[ "$1" == --dbname=service=easy-waf-archive && -z "${DATABASE_URL+x}" ]]
[[ "$*" != *fixture:special* && "$*" != *fixture%3A* && "$*" != *'fixture trailing'* ]]
[[ "$(stat -c %a "$PGSERVICEFILE")" == 600 ]]
exec "$REAL_DUMP" "$@"
MOCK
sed 's/REAL_DUMP/REAL_RESTORE/g' "$work/bin/pg_dump" >"$work/bin/pg_restore"
chmod 0700 "$work/bin/"*
export PATH="$work/bin:$PATH"
export DATABASE_URL='fixture inherited connection settings'
dsn='postgresql://fixture:fixture%3Aspecial%40value@127.0.0.1:55477/archive_source?sslmode=disable'
[[ "$(python3 -I "$SCRIPT_DIR/../lib/pg-archive.py" "$work/private" psql -XwAt \
  -c 'SELECT value FROM evidence' <<<"$dsn")" == fixture ]]
python3 -I "$SCRIPT_DIR/../lib/pg-archive.py" "$work/private" pg_dump -Fc -f "$work/data.pg" <<<"$dsn"
service="$work/operator-service.conf"
printf '[selected]\nhost=127.0.0.1\nport=55477\nuser=fixture\ndbname=archive_target\npassword=overridden\nsslmode=disable\n' >"$service"
PGSERVICEFILE="$service" python3 -I "$SCRIPT_DIR/../lib/pg-archive.py" "$work/private" pg_restore \
  --single-transaction --no-owner "$work/data.pg" <<<"service=selected password='fixture:special@value'"
[[ "$(psql -XwAt -d archive_target -c 'SELECT value FROM evidence')" == fixture ]]
echo 'OK: libpq kept SCRAM credentials off argv and preserved URI and service precedence'

# When libpq cannot preserve trailing whitespace in the private service file,
# it still accepts the original value through its corresponding env variable.
psql -Xw -d postgres -v ON_ERROR_STOP=1 -q <<'SQL'
ALTER ROLE fixture PASSWORD 'fixture trailing space ';
SQL
dsn='postgres://fixture:fixture%20trailing%20space%20@127.0.0.1:55477/archive_source?sslmode=disable'
python3 -I "$SCRIPT_DIR/../lib/pg-archive.py" "$work/private" pg_dump -Fc -f "$work/data.pg" <<<"$dsn"
echo 'OK: libpq environment fallback preserved an exact password with trailing whitespace'

if python3 -I "$SCRIPT_DIR/../lib/pg-archive.py" "$work/private" pg_dump \
    >"$work/parse-output" 2>&1 <<<"password='fixture-parse-marker"; then
  echo 'ERROR: accepted malformed connection parameters' >&2
  exit 1
fi
grep -Fq 'could not load PostgreSQL connection settings' "$work/parse-output"
if grep -Fq 'fixture-parse-marker' "$work/parse-output"; then
  echo 'ERROR: parse diagnostic exposed the input' >&2
  exit 1
fi
