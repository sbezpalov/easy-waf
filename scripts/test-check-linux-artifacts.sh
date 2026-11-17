#!/usr/bin/env bash
# Exercise the actual formatter gate on a checkout and a source archive.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if ! command -v git >/dev/null || ! command -v gofmt >/dev/null; then
  echo 'SKIP: Git and gofmt are required for formatter gate tests'
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
git_local_vars="$(git rev-parse --local-env-vars)"
while IFS= read -r name; do unset "$name"; done <<<"$git_local_vars"
cd "$WORK"
mkdir -p checkout/{scripts,.ai,dist,vendor,"space dir"} archive/scripts
cp "$SCRIPT_DIR/check-linux-artifacts.sh" checkout/scripts/
cp "$SCRIPT_DIR/check-linux-artifacts.sh" archive/scripts/
fail() { echo "FAIL: $*" >&2; exit 1; }

printf 'package fixture\n' >checkout/prod.go
printf 'package fixture\n' >'checkout/space dir/working file.go'
printf '/.ai/\n/dist/\n' >checkout/.gitignore
git -C checkout init -q
git -C checkout add prod.go 'space dir/working file.go'
printf 'package fixture; var x= 1\n' >checkout/.ai/generated.go
printf 'package fixture; var x= 1\n' >checkout/dist/generated.go
printf 'package fixture; var x= 1\n' >checkout/vendor/generated.go
bash checkout/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1 ||
  fail 'checkout gate scanned generated artifacts or vendor'

printf 'package fixture; var x= 1\n' >checkout/untracked.go
if bash checkout/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1; then
  fail 'checkout gate missed an unformatted new file'
fi
grep -q 'untracked.go' "$WORK/check.log" || fail 'new file absent from formatter output'
rm checkout/untracked.go 'checkout/space dir/working file.go'
bash checkout/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1 ||
  fail 'checkout gate rejected a deleted source file'

printf 'package fixture\nfunc broken(\n' >checkout/prod.go
if bash checkout/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1; then
  fail 'checkout gate swallowed a gofmt parse error'
fi
grep -q 'prod.go' "$WORK/check.log" || fail 'gofmt parse diagnostics were lost'

printf 'package fixture; var x= 1\n' >archive/prod.go
if bash archive/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1; then
  fail 'archive gate missed an unformatted source file'
fi
grep -q 'prod.go' "$WORK/check.log" || fail 'archive source absent from formatter output'
cp -R archive checkout/.ai/
if bash checkout/.ai/archive/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1; then
  fail 'archive nested in another checkout skipped its own source'
fi
grep -q 'prod.go' "$WORK/check.log" || fail 'nested archive source absent from formatter output'
printf 'package fixture\n' >archive/prod.go
bash archive/scripts/check-linux-artifacts.sh >"$WORK/check.log" 2>&1 ||
  fail 'archive gate rejected valid source'

echo 'OK: formatter gate checks checkout and archive sources and preserves errors'
