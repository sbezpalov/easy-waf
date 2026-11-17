#!/usr/bin/env bash
# Stand in for Python/libpq when testing service and filesystem choreography.
set -euo pipefail
[[ "$1" == -I && "$2" == */lib/pg-archive.py && -d "$3" ]]
client="$4"
directory="$3"
[[ "$client" == pg_dump || "$client" == pg_restore || "$client" == psql ]]
shift 4
MOCK_PG_DSN="$(cat)"
export MOCK_PG_DSN
printf '%s' "$MOCK_PG_DSN" >"$directory/pg-service-fixture"
exec "$client" --dbname=service=easy-waf-archive "$@"
