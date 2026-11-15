#!/usr/bin/env bash
# Offline archive validation; fixture payloads are text, never executed.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/release-unpack.sh
source "${SCRIPT_DIR}/lib/release-unpack.sh"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
required=(easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin)
mkdir -p "$ROOT/input/dist" "$ROOT/output"
for binary in "${required[@]}"; do
  printf 'new %s\n' "$binary" >"$ROOT/input/dist/$binary"
  printf 'old %s\n' "$binary" >"$ROOT/output/$binary"
done
fail() { echo "FAIL: $*" >&2; exit 1; }
unchanged() {
  local binary
  for binary in "${required[@]}"; do
    [[ "$(cat "$ROOT/output/$binary")" == "old $binary" ]] || fail "failed extraction replaced $binary"
  done
  [[ -z "$(find "$ROOT/output" -name '.release-stage.*' -print)" ]] || fail 'stage leaked'
}
tar -czf "$ROOT/full.tgz" -C "$ROOT/input" .
bytes="$(wc -c <"$ROOT/full.tgz")"
dd if="$ROOT/full.tgz" of="$ROOT/truncated.tgz" bs=1 count="$((bytes-8))" 2>/dev/null
if easy_waf_unpack_release "$ROOT/truncated.tgz" "$ROOT/output" 2>/dev/null; then fail 'truncated archive accepted'; fi
unchanged
rm "$ROOT/input/dist/easy-waf-admin"
tar -czf "$ROOT/missing.tgz" -C "$ROOT/input" .
if easy_waf_unpack_release "$ROOT/missing.tgz" "$ROOT/output" 2>/dev/null; then fail 'missing component accepted'; fi
unchanged
printf 'admin\n' >"$ROOT/input/dist/easy-waf-admin"
cp "$ROOT/input/dist/easy-waf-api" "$ROOT/input/easy-waf-api"
tar -czf "$ROOT/duplicate.tgz" -C "$ROOT/input" .
if easy_waf_unpack_release "$ROOT/duplicate.tgz" "$ROOT/output" 2>/dev/null; then fail 'ambiguous component accepted'; fi
unchanged
easy_waf_unpack_release "$ROOT/full.tgz" "$ROOT/output" || fail 'complete release rejected'
for binary in "${required[@]}"; do
  [[ "$(cat "$ROOT/output/$binary")" == "new $binary" ]] || fail "wrong promoted $binary"
done
mkdir "$ROOT/flat"
cp "$ROOT/input/dist/"* "$ROOT/flat/"
tar -czf "$ROOT/flat.tgz" -C "$ROOT/flat" .
easy_waf_unpack_release "$ROOT/flat.tgz" "$ROOT/output" || fail 'flat release rejected'

# Execute the actual installer acquisition path, with network/authentication
# replaced by fixtures. A truncated but "verified" archive must not succeed
# merely because tar emitted an API file before reporting its gzip error.
SOURCE_DIR="$SCRIPT_DIR"
REPO_ROOT="$ROOT/repo"
SCRIPT_DIR="$REPO_ROOT/scripts"
DIST_DIR="$REPO_ROOT/dist"
mkdir -p "$SCRIPT_DIR/lib" "$DIST_DIR"
cp "$SOURCE_DIR/lib/release-unpack.sh" "$SCRIPT_DIR/lib/"
cat >"$SCRIPT_DIR/lib/release-verify.sh" <<'MOCK'
easy_waf_curl_https() { cp "$TEST_ARCHIVE" "$2"; }
easy_waf_verify_release_artifact() { return 0; }
easy_waf_verify_sha256() { return 0; }
log_relv() { :; }
MOCK
printf 'easy_waf_github_repo() { echo fixture/repo; }\n' >"$SCRIPT_DIR/lib/github-repo.sh"
printf 'easy_waf_release_arch() { echo amd64; }\n' >"$SCRIPT_DIR/lib/release-arch.sh"
function_source="$(sed -n '/^acquire_dist_binaries() {$/,/^}$/p' "$SOURCE_DIR/install.sh")"
[[ -n "$function_source" ]] || fail 'missing installer acquisition function'
eval "$function_source"
log() { :; }
die() { exit 1; }
easy_waf_target_version() { echo 9.9.9; }
curl() { fail 'unexpected direct network call'; }
export EASY_WAF_PKG_INSTALLED=0
export EASY_WAF_OFFLINE=0
export EASY_WAF_SKIP_BINARY_FETCH=0
export EASY_WAF_BUILD_FROM_SOURCE=0
export TEST_ARCHIVE="$ROOT/truncated.tgz"
printf 'old hostd\n' >"$DIST_DIR/easy-waf-hostd"
if (acquire_dist_binaries) >/dev/null 2>&1; then fail 'installer accepted truncated archive'; fi
[[ ! -e "$DIST_DIR/easy-waf-api" ]] || fail 'installer left a partial API binary'
[[ "$(cat "$DIST_DIR/easy-waf-hostd")" == 'old hostd' ]] || fail 'installer replaced existing hostd on failure'

# Check both real downloader entry paths with the same private network/auth
# stand-ins. Rejected archives must not leave nested dist/ extraction debris.
cp "$SOURCE_DIR/download-release.sh" "$SCRIPT_DIR/"
export EASY_WAF_RELEASE_URL='https://fixture.example/release.tgz'
export EASY_WAF_RELEASE_SHA256='fixture-authentication-is-mocked'
for archive in truncated missing; do
  export TEST_ARCHIVE="$ROOT/$archive.tgz"
  if bash "$SCRIPT_DIR/download-release.sh" >/dev/null 2>&1; then fail "downloader accepted $archive archive"; fi
  [[ ! -e "$DIST_DIR/easy-waf-api" && ! -e "$DIST_DIR/dist" ]] || fail 'downloader left partial files'
  [[ "$(cat "$DIST_DIR/easy-waf-hostd")" == 'old hostd' ]] || fail 'downloader changed old files on failure'
done
export TEST_ARCHIVE="$ROOT/full.tgz"
bash "$SCRIPT_DIR/download-release.sh" >/dev/null || fail 'custom downloader rejected complete release'
unset EASY_WAF_RELEASE_URL
export EASY_WAF_VERSION=9.9.9
bash "$SCRIPT_DIR/download-release.sh" >/dev/null || fail 'versioned downloader rejected complete release'
for binary in "${required[@]}"; do
  [[ "$(cat "$DIST_DIR/$binary")" == "new $binary" ]] || fail "downloader did not publish $binary"
done
echo 'OK: release unpack checks passed'
