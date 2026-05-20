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

echo "== Checking shell scripts for CRLF (Windows line endings) =="
_sh_crlf=0
while IFS= read -r -d '' f; do
  if grep -q $'\r' "$f" 2>/dev/null; then
    echo "ERROR: CRLF in $f — use LF only (.gitattributes). Re-save as Unix or: sed -i 's/\\r$//' \"$f\"" >&2
    _sh_crlf=1
  fi
done < <(find scripts -name '*.sh' -type f -print0 2>/dev/null || true)
if [[ "$_sh_crlf" -ne 0 ]]; then
  exit 1
fi
echo "OK (shell scripts are LF-only)"

echo "== gofmt (if go is installed) =="
if command -v gofmt &>/dev/null; then
  _fmt_out="$(gofmt -l . 2>/dev/null | grep -v '^vendor/' || true)"
  if [[ -n "$_fmt_out" ]]; then
    echo "ERROR: gofmt needed on:" >&2
    echo "$_fmt_out" >&2
    echo "Run: gofmt -w ." >&2
    exit 1
  fi
  echo "OK"
else
  echo "SKIP (gofmt not in PATH)"
fi

echo "== Scanning docs/configs for Windows drive-letter paths (C:\\...) =="
# Do not scan scripts/*.sh: JSON \" escapes and regex \\s false-positive here.
if grep -RE '[A-Za-z]:\\' --include='*.example' --include='*.md' --include='*.service' \
  configs packaging docs 2>/dev/null; then
  echo "WARNING: possible Windows paths in docs/configs — use forward slashes for Linux." >&2
else
  echo "OK (no Windows drive-letter paths in docs/configs)"
fi
echo "Done."
