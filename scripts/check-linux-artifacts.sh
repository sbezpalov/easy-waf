#!/usr/bin/env bash
# Clean Windows build junk locally, then fail CI if .exe is tracked or shell has CRLF.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== Cleaning Windows-style artifacts under dist/ (working tree only) =="
if [[ -d dist ]]; then
  while IFS= read -r -d '' f; do
    echo "Removing $f"
    rm -f "$f"
  done < <(find dist -maxdepth 1 -type f \( -iname '*.exe' -o -iname '*.dll' \) -print0 2>/dev/null || true)
fi
echo "OK"

echo "== Checking for committed Windows binaries =="
if git ls-files 2>/dev/null | grep -E '\.(exe|EXE|dll|DLL)$'; then
  echo "ERROR: Do not commit Windows binaries (.exe/.dll) — Linux target only." >&2
  exit 1
fi
echo "OK (no .exe/.dll in git index)"

echo "== Checking shell files for CRLF (Windows line endings) =="
_sh_crlf=0
while IFS= read -r -d '' f; do
  if grep -q $'\r' "$f" 2>/dev/null; then
    printf 'ERROR: CRLF in %s — use LF only (.gitattributes). Re-save with Unix line endings.\n' "$f" >&2
    _sh_crlf=1
  fi
done < <(
  find scripts -name '*.sh' -type f -print0 2>/dev/null || true
  find packaging/deb -maxdepth 1 -type f -print0 2>/dev/null || true
  find packaging/ovf -name '*.sh' -type f -print0 2>/dev/null || true
)
if [[ "$_sh_crlf" -ne 0 ]]; then
  exit 1
fi
echo "OK (shell files are LF-only)"

go_source_files() {
  local prefix
  if prefix="$(git rev-parse --show-prefix 2>/dev/null)" && [[ -z "$prefix" ]]; then
    git ls-files --cached --others --exclude-standard -z -- '*.go' ':!vendor/**'
  else
    find . \( -path ./.git -o -path ./.ai -o -path ./dist -o -path ./vendor \) -prune \
      -o -type f -name '*.go' -print0
  fi
}

echo "== gofmt (if go is installed) =="
if command -v gofmt &>/dev/null; then
  if ! _fmt_out="$(go_source_files |
    while IFS= read -r -d '' file; do
      if [[ -f "$file" ]]; then printf '%s\0' "$file"; fi
    done | xargs -0 -n 64 gofmt -l --)"; then
    echo "ERROR: gofmt check failed" >&2
    exit 1
  fi
  if [[ -n "$_fmt_out" ]]; then
    echo "ERROR: gofmt needed on:" >&2
    echo "$_fmt_out" >&2
    echo "Run gofmt -w on the listed files." >&2
    exit 1
  fi
  echo "OK"
else
  echo "SKIP (gofmt not in PATH)"
fi

echo "== Scanning docs/configs for Windows drive-letter paths (C:\\...) =="
# Do not scan scripts/*.sh: JSON \" escapes and regex \\s false-positive here.
if grep -RE "[A-Za-z]:\\\\" --include='*.example' --include='*.md' --include='*.service' \
  configs packaging docs 2>/dev/null; then
  echo "WARNING: possible Windows paths in docs/configs — use forward slashes for Linux." >&2
else
  echo "OK (no Windows drive-letter paths in docs/configs)"
fi
echo "Done."
