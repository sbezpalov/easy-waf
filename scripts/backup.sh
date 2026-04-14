#!/usr/bin/env bash
set -euo pipefail
STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"
OUT="${1:-easy-waf-backup-$(date +%Y%m%d-%H%M%S).tar.gz}"
tar -czf "$OUT" -C "$(dirname "$STATE")" "$(basename "$STATE")" /etc/easy-waf 2>/dev/null || tar -czf "$OUT" -C "$(dirname "$STATE")" "$(basename "$STATE")"
echo "$OUT"
