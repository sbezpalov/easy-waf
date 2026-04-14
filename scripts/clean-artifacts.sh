#!/usr/bin/env bash
# Remove Windows build outputs from dist/ only (safe; does not touch tracked sources).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[[ -d dist ]] || exit 0
find dist -maxdepth 1 -type f \( -iname '*.exe' -o -iname '*.dll' \) -print -delete 2>/dev/null || true
echo "clean-artifacts: done"
