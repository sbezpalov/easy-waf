#!/usr/bin/env bash
# Stand in for Python/libpq when testing service and filesystem choreography.
set -euo pipefail
[[ "$1" == -I && "$2" == */lib/pg-archive.py && -d "$3" ]]
client="$4"
[[ "$client" == pg_dump || "$client" == pg_restore ]]
shift 4
MOCK_PG_DSN="$(cat)"
export MOCK_PG_DSN
exec "$client" --dbname=service=easy-waf-archive "$@"
