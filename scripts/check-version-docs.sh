#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

version="$(tr -d '[:space:]' <VERSION)"
[[ -n "$version" ]] || {
  echo "[version-docs] VERSION is empty" >&2
  exit 1
}

failed=0
check_line() {
  local file="$1"
  local expected="$2"
  if ! grep -Fq -- "$expected" "$file"; then
    printf '[version-docs] %s does not contain: %s\n' "$file" "$expected" >&2
    failed=1
  fi
}

check_line AGENTS.md "- **Версия:** \`$version\`"
check_line CHANGELOG.md "- **VERSION** is \`$version\` on \`main\`"
check_line docs/ARCHITECTURE.md "aligned with root [\`VERSION\`](../VERSION) (**$version**)"
check_line docs/DEPLOYMENT.md "root [\`VERSION\`](../VERSION) (**$version**)"
check_line docs/IMPLEMENTATION_STATUS.md "**Current VERSION:** $version"
check_line docs/OPERATIONS.md "[\`VERSION\`](../VERSION) — **$version**"
check_line docs/QUICKSTART.md "[\`VERSION\`](../VERSION) in the repo (**$version**)"
check_line docs/QUICKSTART.ru.md "Переведено с $version."
check_line docs/QUICKSTART.ru.md "[\`VERSION\`](../VERSION) в корне репозитория (**$version**)"
check_line docs/SECURITY.md "[\`VERSION\`](../VERSION) (**$version**)"
check_line docs/SECURITY.ru.md "Переведено с $version."
check_line docs/SECURITY.ru.md "[\`VERSION\`](../VERSION) (**$version**)"
check_line docs/TROUBLESHOOTING.md "tree version **$version**"
check_line docs/TROUBLESHOOTING.ru.md "Переведено с $version."
check_line docs/TROUBLESHOOTING.ru.md "версии дерева **$version**"

if ((failed)); then
  exit 1
fi
printf '[version-docs] current-version references match VERSION=%s\n' "$version"
