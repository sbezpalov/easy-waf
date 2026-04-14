#!/usr/bin/env bash
set -euo pipefail
ARCHIVE="${1:?usage: restore.sh backup.tar.gz}"
STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
tar -xzf "$ARCHIVE" -C "$(dirname "$STATE")"
echo "Restored into $(dirname "$STATE") — restart easy-wafd and validate HAProxy"
