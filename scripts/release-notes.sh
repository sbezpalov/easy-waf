#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
# Print one validated release section; failures never emit partial notes.
set -euo pipefail
if (($# < 1 || $# > 2)); then
  echo "Usage: bash $0 VERSION [CHANGELOG.md]" >&2
  exit 2
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
version="$1"
changelog="${2:-$SCRIPT_DIR/../CHANGELOG.md}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
  echo 'ERROR: expected a release version such as 1.6.1 or 1.7.0-rc.1' >&2
  exit 1
fi
if [[ ! -f "$changelog" || ! -r "$changelog" ]]; then
  echo "ERROR: cannot read changelog: $changelog" >&2
  exit 1
fi
if ! notes="$(awk -v version="$version" '
  BEGIN { header = "## [" version "]" }
  {
    sub(/\r$/, "")
    if ($0 ~ /^##[[:space:]]/) {
      selected = index($0, header) == 1
      if (selected) sections++
      next
    }
    if (selected) {
      notes = notes $0 "\n"
      if ($0 ~ /[^[:space:]]/) nonempty = 1
    }
  }
  END {
    if (sections != 1 || !nonempty) exit 1
    printf "%s", notes
  }
' <"$changelog")"; then
  echo "ERROR: $changelog requires exactly one nonempty section ## [$version]" >&2
  exit 1
fi
printf '%s\n' "$notes"
