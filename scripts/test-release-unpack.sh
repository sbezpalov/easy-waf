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
(
  mv() {
    if [[ "$2" == */.release-stage.*/easy-waf-api && "$3" == "$ROOT/output/easy-waf-api" ]]; then
      return 48
    fi
    command mv "$@"
  }
  if easy_waf_unpack_release "$ROOT/full.tgz" "$ROOT/output" 2>/dev/null; then fail 'promotion failure reported success'; fi
  unchanged
  rm -- "$ROOT/output/easy-waf-hostd"
  if easy_waf_unpack_release "$ROOT/full.tgz" "$ROOT/output" 2>/dev/null; then fail 'promotion failure reported success for a new file'; fi
  [[ ! -e "$ROOT/output/easy-waf-hostd" ]] || fail 'promotion failure left a new binary'
  printf 'old easy-waf-hostd\n' >"$ROOT/output/easy-waf-hostd"
  unchanged
)
(
  degraded="$ROOT/degraded"
  mkdir "$degraded"
  printf 'previous hostd\n' >"$degraded/easy-waf-hostd"
  mv() {
    case "$2" in
      */.release-stage.*/easy-waf-api|*/.release-stage.*/previous/easy-waf-hostd) return 48 ;;
    esac
    command mv "$@"
  }
  if easy_waf_unpack_release "$ROOT/full.tgz" "$degraded" >"$ROOT/rollback.log" 2>&1; then
    fail 'incomplete rollback reported success'
  fi
  grep -Fq 'rollback incomplete; recovery files retained' "$ROOT/rollback.log" || fail 'missing rollback recovery notice'
  previous=("$degraded"/.release-stage.*/previous/easy-waf-hostd)
  [[ ${#previous[@]} == 1 && -f "${previous[0]}" && "$(cat "${previous[0]}")" == 'previous hostd' ]] ||
    fail 'incomplete rollback lost the previous binary'
)
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
easy_waf_curl_https() {
  if [[ "${TEST_CUSTOM_RELEASE:-}" == 1 ]]; then
    [[ "${EASY_WAF_RELEASE_URL+x}" != x ]] || return 99
    [[ "$#" == 5 && "$1" == --globoff && "$2" == -o && "$4" == --config && "$5" == - ]] || return 99
    local config
    IFS= read -r config || return 99
    [[ "$config" == "$TEST_RELEASE_CONFIG" ]] || return 99
    if [[ "${TEST_MIRROR_FAIL:-}" == 1 ]]; then
      printf '%s\n' "$config" >&2
      printf '%s\n' "$config"
      return 22
    fi
    cp "$TEST_ARCHIVE" "$3"
    return
  fi
  cp "$TEST_ARCHIVE" "$2"
}
easy_waf_verify_release_artifact() { return 0; }
easy_waf_verify_sha256() { return 0; }
log_relv() { printf '%s\n' "$*"; }
MOCK
printf 'easy_waf_github_repo() { echo fixture/repo; }\n' >"$SCRIPT_DIR/lib/github-repo.sh"
printf 'easy_waf_release_arch() { echo amd64; }\n' >"$SCRIPT_DIR/lib/release-arch.sh"
function_source="$(sed -n -e '/^dist_binaries_complete() {$/,/^}$/p' -e '/^check_local_only_binaries() {$/,/^}$/p' \
  -e '/^acquire_dist_binaries() {$/,/^}$/p' -e '/^install_binaries() {$/,/^}$/p' "$SOURCE_DIR/install.sh")"
[[ -n "$function_source" ]] || fail 'missing installer acquisition function'
eval "$function_source"
log() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
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
export EASY_WAF_RELEASE_URL='https://fixture.example/release.tgz?token=fixture-private-token&label="a\b"'
export TEST_RELEASE_CONFIG='url = "https://fixture.example/release.tgz?token=fixture-private-token&label=\"a\\b\""'
export TEST_CUSTOM_RELEASE=1
export EASY_WAF_RELEASE_SHA256='fixture-authentication-is-mocked'
for archive in truncated missing; do
  export TEST_ARCHIVE="$ROOT/$archive.tgz"
  if bash "$SCRIPT_DIR/download-release.sh" >/dev/null 2>&1; then fail "downloader accepted $archive archive"; fi
  [[ ! -e "$DIST_DIR/easy-waf-api" && ! -e "$DIST_DIR/dist" ]] || fail 'downloader left partial files'
  [[ "$(cat "$DIST_DIR/easy-waf-hostd")" == 'old hostd' ]] || fail 'downloader changed old files on failure'
done
export TEST_ARCHIVE="$ROOT/full.tgz"
bash -x "$SCRIPT_DIR/download-release.sh" >"$ROOT/download.log" 2>&1 || fail 'custom downloader rejected complete release'
if grep -Fq 'fixture-private-token' "$ROOT/download.log"; then fail 'custom downloader exposed the URL'; fi
if TEST_MIRROR_FAIL=1 bash -x "$SCRIPT_DIR/download-release.sh" >"$ROOT/download.log" 2>&1; then
  fail 'custom downloader accepted a failed transfer'
fi
if grep -Fq 'fixture-private-token' "$ROOT/download.log"; then fail 'custom downloader exposed a failing URL'; fi
grep -Fq 'download from the configured release URL failed' "$ROOT/download.log" || fail 'missing transfer error'
if EASY_WAF_RELEASE_URL="$EASY_WAF_RELEASE_URL"$'\n' bash "$SCRIPT_DIR/download-release.sh" >"$ROOT/download.log" 2>&1; then
  fail 'custom downloader accepted a control character'
fi
grep -Fq 'control characters' "$ROOT/download.log" || fail 'missing invalid URL error'
unset EASY_WAF_RELEASE_URL TEST_CUSTOM_RELEASE
export EASY_WAF_VERSION=9.9.9
bash "$SCRIPT_DIR/download-release.sh" >/dev/null || fail 'versioned downloader rejected complete release'
for binary in "${required[@]}"; do
  [[ "$(cat "$DIST_DIR/$binary")" == "new $binary" ]] || fail "downloader did not publish $binary"
done
(
  EASY_WAF_SKIP_BINARY_FETCH=1 acquire_dist_binaries
  : >"$DIST_DIR/easy-waf-hostd"
  if (EASY_WAF_SKIP_BINARY_FETCH=1 acquire_dist_binaries) >/dev/null 2>&1; then
    fail 'installer accepted an empty local binary'
  fi
  # shellcheck disable=SC2317,SC2329 # Called by the installer function loaded with eval.
  install() { : >"$ROOT/local-install-called"; }
  if (install_binaries) >/dev/null 2>&1; then fail 'incomplete set passed installation preflight'; fi
  [[ ! -e "$ROOT/local-install-called" ]] || fail 'installer copied a file before rejecting the incomplete set'
)

# A missing download capability is not permission to install a compiler. Model
# that host without removing tools from the developer's machine or real PATH.
for binary in "${required[@]}"; do rm "$DIST_DIR/$binary"; done
: >"$REPO_ROOT/Makefile"
command() {
  if [[ "${1:-}" == -v && "${2:-}" == curl ]]; then return 1; fi
  builtin command "$@"
}
easy_waf_apt_get_update() { : >"$ROOT/toolchain-attempt"; }
apt-get() { return 0; }
easy_waf_go_version_meets() { return 0; }
go() { return 0; }
# shellcheck disable=SC2317,SC2329 # Called by the installer function loaded with eval.
make() { return 1; }
export EASY_WAF_INSTALL_BUILD_DEPS=1
export EASY_WAF_PKG_MGR=apt
if (acquire_dist_binaries) >/dev/null 2>&1; then fail 'missing curl unexpectedly succeeded'; fi
[[ ! -e "$ROOT/toolchain-attempt" ]] || fail 'missing curl implicitly enabled source build'
export EASY_WAF_BUILD_FROM_SOURCE=1
(acquire_dist_binaries) >/dev/null 2>&1 || true # fixture make deliberately fails
[[ -e "$ROOT/toolchain-attempt" ]] || fail 'explicit source build was not honored'
make() { printf 'partial build\n' >"$DIST_DIR/easy-waf-api"; }
if (acquire_dist_binaries) >"$ROOT/partial-build.log" 2>&1; then fail 'installer accepted a partial source build'; fi
grep -Fq 'Build did not produce a complete binary set' "$ROOT/partial-build.log" || fail 'missing partial build diagnosis'
echo 'OK: release unpack checks passed'
