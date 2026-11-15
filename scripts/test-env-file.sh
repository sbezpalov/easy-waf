#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/env-file.sh
source "${SCRIPT_DIR}/lib/env-file.sh"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/easy-waf-env-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

MARKER="$TMP/executed"
ENV_FILE="$TMP/test.env"
cat >"$ENV_FILE" <<EOF
DATABASE_URL='postgres://first'
MALICIOUS=\$(touch "$MARKER")
DATABASE_URL="postgres://user:pass@db/easywaf?sslmode=disable"
EOF

value="$(easy_waf_read_env_value "$ENV_FILE" DATABASE_URL)"
[[ "$value" == "postgres://user:pass@db/easywaf?sslmode=disable" ]]
[[ ! -e "$MARKER" ]]
[[ -z "$(easy_waf_read_env_value "$ENV_FILE" MISSING)" ]]

(
  export ENV_TEST_KEEP=existing ENV_TEST_EMPTY=stale
  unset DATABASE_URL MALICIOUS
  printf 'ENV_TEST_EMPTY=\n' >>"$ENV_FILE"
  easy_waf_export_env_keys "$ENV_FILE" DATABASE_URL ENV_TEST_KEEP ENV_TEST_EMPTY
  [[ "$DATABASE_URL" == "$value" && "$ENV_TEST_KEEP" == existing && -z "$ENV_TEST_EMPTY" ]]
  [[ -z "${MALICIOUS+x}" && ! -e "$MARKER" ]]
  bash -c '[[ -n "$DATABASE_URL" && "$ENV_TEST_KEEP" == existing && -z "$ENV_TEST_EMPTY" ]]'
  if easy_waf_export_env_keys "$ENV_FILE" 'BAD.*'; then
    echo 'invalid env key accepted' >&2; exit 1
  fi
  if easy_waf_export_env_keys "$TMP/missing" DATABASE_URL; then
    echo 'missing env file accepted' >&2; exit 1
  fi
)

echo "env-file parser: OK"
