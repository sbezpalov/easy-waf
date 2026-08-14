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

echo "env-file parser: OK"
