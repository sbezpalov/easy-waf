#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXTRACTOR="${EASY_WAF_RELEASE_NOTES_TEST_SCRIPT:-$SCRIPT_DIR/release-notes.sh}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
reject() {
  local name="$1" version="$2"
  if bash "$EXTRACTOR" "$version" "$WORK/changelog" >"$WORK/output" 2>"$WORK/error"; then
    fail "$name accepted"
  fi
  [[ ! -s "$WORK/output" ]] || fail "$name emitted partial notes"
  echo "PASS: release notes reject $name"
}
accept() {
  local name="$1" version="$2"
  bash "$EXTRACTOR" "$version" "$WORK/changelog" >"$WORK/output" || fail "$name rejected"
  [[ "$(cat "$WORK/output")" == 'Expected entry' ]] || fail "$name selected wrong or unnormalized notes"
  echo "PASS: release notes $name"
}

printf '## [1x6y1]\nWrong version\n' >"$WORK/changelog"
reject regex_lookalike 1.6.1
printf '## [Unreleased]\nFuture entry\n## [1.6.10]\nOther version\n## [1.6.1] - 2026-11-16\nExpected entry\n## [1.6.0]\nOlder entry\n' >"$WORK/changelog"
accept exact_version 1.6.1
printf '## [1.7.0-rc.1+build.2]\nExpected entry\n## Appendix\nExcluded appendix\n' >"$WORK/changelog"
accept prerelease_metadata 1.7.0-rc.1+build.2
printf '## [1.6.1]\r\nExpected entry\r\n## [1.6.0]\r\nOld\r\n' >"$WORK/changelog"
accept crlf 1.6.1
printf '## [Unreleased]\nFuture entry\n' >"$WORK/changelog"
reject missing_version 1.6.1
printf '## [1.6.1]\n \t\n\n## [1.6.0]\nOlder entry\n' >"$WORK/changelog"
reject whitespace_only 1.6.1
printf '## [1.6.1]\nFirst\n## [1.6.1]\nSecond\n' >"$WORK/changelog"
reject duplicate_version 1.6.1
: >"$WORK/changelog"
reject empty_file 1.6.1
printf '## [1.6.10]\nWrong version\n' >"$WORK/changelog"
reject version_prefix 1.6.1
printf '## [1.6.1]\nExpected entry\n' >"$WORK/changelog"
reject invalid_version $'1.6.1\ninvalid'

# Execute the actual workflow preflight in a private checkout-shaped fixture.
# Fake following tools prove a bad tag/notes gate cannot reach expensive work.
WORKFLOW="$SCRIPT_DIR/../.github/workflows/release.yml"
preflight_line="$(grep -n '^      - name: Validate release metadata and prepare notes$' "$WORKFLOW" | cut -d: -f1)"
[[ "$preflight_line" =~ ^[0-9]+$ ]] || fail 'missing or duplicate workflow preflight'
for step in 'Setup Go' 'Install nfpm' 'Build amd64 and arm64 tarballs and packages' 'Install cosign' 'Sign SHA256SUMS' 'Create GitHub Release'; do
  line="$(grep -n -m 1 "^      - name: $step$" "$WORKFLOW" | cut -d: -f1)"
  [[ "$line" =~ ^[0-9]+$ && "$preflight_line" -lt "$line" ]] || fail "preflight must precede $step"
done
awk '
  /^      - name: Validate release metadata and prepare notes$/ { selected = 1; next }
  selected && /^        run: \|$/ { body = 1; next }
  body && /^          / { sub(/^          /, ""); print; next }
  body && /^[[:space:]]*$/ { next }
  body { exit }
' "$WORKFLOW" >"$WORK/preflight.sh"
[[ -s "$WORK/preflight.sh" ]] || fail 'missing workflow preflight body'
printf '\ngo version\nnfpm --version\ncosign version\n' >>"$WORK/preflight.sh"
mkdir -p "$WORK/repo/scripts" "$WORK/bin"
cp "$EXTRACTOR" "$WORK/repo/scripts/release-notes.sh"
printf '1.6.1\n' >"$WORK/repo/VERSION"
export RELEASE_NOTES_TEST_CALLS="$WORK/calls"
for tool in go nfpm cosign; do
  cat >"$WORK/bin/$tool" <<'MOCK'
#!/bin/sh
printf 'called\n' >>"$RELEASE_NOTES_TEST_CALLS"
MOCK
  chmod 0700 "$WORK/bin/$tool"
done
export PATH="$WORK/bin:$PATH"
for scenario in mismatched_tag missing_notes empty_notes ready; do
  : >"$WORK/calls"
  tag=v1.6.1
  case "$scenario" in
    mismatched_tag) tag=v1.6.2; printf '## [1.6.1]\nExpected entry\n' >"$WORK/repo/CHANGELOG.md" ;;
    missing_notes) printf '## [Unreleased]\nFuture entry\n' >"$WORK/repo/CHANGELOG.md" ;;
    empty_notes) printf '## [1.6.1]\n \t\n' >"$WORK/repo/CHANGELOG.md" ;;
    ready) printf '## [1.6.1]\nExpected entry\n' >"$WORK/repo/CHANGELOG.md" ;;
  esac
  result=0
  (cd "$WORK/repo"; GITHUB_REF_NAME="$tag" bash "$WORK/preflight.sh") >"$WORK/$scenario.log" 2>&1 || result=$?
  if [[ "$scenario" == ready ]]; then
    [[ "$result" == 0 ]] || fail 'valid workflow metadata rejected'
    [[ "$(wc -l <"$WORK/calls")" -eq 3 ]] || fail 'valid metadata did not reach following tools'
    [[ "$(cat "$WORK/repo/release_notes.md")" == 'Expected entry' ]] || fail 'wrong prepared release body'
  else
    [[ "$result" != 0 && ! -s "$WORK/calls" ]] || fail "$scenario reached following tools"
  fi
  echo "PASS: workflow release preflight $scenario"
done
