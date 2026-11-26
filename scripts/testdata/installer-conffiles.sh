#!/usr/bin/env bash
# Actual conffile decisions in a private dpkg root; no maintainer scripts/services.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
# Redirect only the CrowdSec function's unrelated directory creation.
mkdir() {
  if [[ "$*" == '-p /etc/haproxy/errors' ]]; then return 0; fi
  command mkdir "$@"
}
APT_REAL="$(type -P apt-get)"
DPKG_REAL="$(type -P dpkg)"
export APT_REAL DPKG_REAL
command mkdir -p "$ROOT/bin" "$ROOT/repo/dist"
cat >"$ROOT/bin/apt-get" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" != update ]] || exit 0
if [[ "${CONFFILE_TEST_PARTIAL:-0}" == 1 ]]; then
  "$DPKG_REAL" --root="$CONFFILE_TEST_ROOT" --log="$CONFFILE_TEST_ROOT/log/dpkg.log" \
    --force-confold --unpack "$CONFFILE_TEST_DEB" || exit $?
  exit 100
fi
args=()
for arg in "$@"; do
  if [[ "$arg" == crowdsec-haproxy-spoa-bouncer ]]; then arg="$CONFFILE_TEST_DEB"; fi
  if [[ "${CONFFILE_TEST_REPO_SELECTION:-0}" == 1 && "${arg##*/}" == "${CONFFILE_TEST_DEB##*/}" ]]; then arg=easy-waf; fi
  args+=("$arg")
done
export APT_CONFIG="$CONFFILE_TEST_ROOT/apt-bootstrap.conf"
exec "$APT_REAL" \
  -o "Dir::Etc::main=$CONFFILE_TEST_ROOT/apt.conf" \
  -o "Dir::Etc::parts=$CONFFILE_TEST_ROOT/apt.conf.d" \
  -o "Dir::State=$CONFFILE_TEST_ROOT/state" \
  -o "Dir::State::extended_states=$CONFFILE_TEST_ROOT/state/extended_states" \
  -o "Dir::State::status=$CONFFILE_TEST_ROOT/var/lib/dpkg/status" \
  -o "Dir::State::lists=$CONFFILE_TEST_ROOT/lists" \
  -o "Dir::Cache=$CONFFILE_TEST_ROOT/cache" \
  -o "Dir::Cache::archives=$CONFFILE_TEST_ROOT/cache/archives" \
  -o "Dir::Log=$CONFFILE_TEST_ROOT/log" \
  -o 'Dir::Log::Terminal=' -o 'Dir::Log::History=' \
  -o "Dir::Etc::sourcelist=$CONFFILE_TEST_ROOT/sources.list" \
  -o "Dir::Etc::sourceparts=$CONFFILE_TEST_ROOT/sources.list.d" \
  -o 'APT::Sandbox::User=root' \
  -o "DPkg::Options::=--root=$CONFFILE_TEST_ROOT" "${args[@]}"
MOCK
cat >"$ROOT/bin/curl" <<'MOCK'
#!/bin/sh
: >"$CONFFILE_TEST_CURL_CALLED"
exit 99
MOCK
CONFFILE_TEST_CURL_CALLED="$ROOT/curl-called"
export CONFFILE_TEST_CURL_CALLED
chmod 0700 "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"
REPO_ROOT="$ROOT/repo"
export EASY_WAF_PKG_MGR=apt
EASY_WAF_PKG_INSTALLED=0
# shellcheck source=../lib/os-pkg.sh
source "$SCRIPT_DIR/lib/os-pkg.sh"
log() { printf '%s\n' "$*"; }
die() { fail "$*"; }
# Called by install_release_package, which the fixture loads below.
# shellcheck disable=SC2329
easy_waf_apt_get_update() { :; }
for function_name in easy_waf_target_version release_package_enabled install_release_package; do
  function_source="$(sed -n "/^${function_name}() {$/,/^}$/p" "$SCRIPT_DIR/install.sh")"
  [[ -n "$function_source" ]] || fail 'installer function missing'
  eval "$function_source"
done
# shellcheck source=../lib/crowdsec-install.sh
source "$SCRIPT_DIR/lib/crowdsec-install.sh"
new_root() {
  CONFFILE_TEST_ROOT="$ROOT/$1"
  export CONFFILE_TEST_ROOT
  command mkdir -p "$CONFFILE_TEST_ROOT"/{etc/easy-waf,var/lib/dpkg,lists/partial,cache/archives/partial,log,state,apt.conf.d,sources.list.d}
  : >"$CONFFILE_TEST_ROOT/var/lib/dpkg/status"
  : >"$CONFFILE_TEST_ROOT/apt.conf"
  : >"$CONFFILE_TEST_ROOT/sources.list"
  printf 'Dir::Etc::main "%s/apt.conf";\nDir::Etc::parts "%s/apt.conf.d";\n' \
    "$CONFFILE_TEST_ROOT" "$CONFFILE_TEST_ROOT" >"$CONFFILE_TEST_ROOT/apt-bootstrap.conf"
  export APT_CONFIG="$CONFFILE_TEST_ROOT/apt-bootstrap.conf"
}
build_deb() {
  local version="$1" vendor="$2" payload="${3:-$2}" stage
  stage="$(mktemp -d "$ROOT/pkg.XXXXXX")"
  command mkdir -p "$stage/DEBIAN" "$stage/etc/easy-waf" "$stage/usr/share/easy-waf"
  printf 'Package: easy-waf\nVersion: %s\nArchitecture: %s\nMaintainer: Fixture <fixture@example.invalid>\nDescription: conffile test only\n' \
    "$version" "$(dpkg --print-architecture)" >"$stage/DEBIAN/control"
  printf '/etc/easy-waf/easy-waf.env\n' >"$stage/DEBIAN/conffiles"
  printf '%s\n' "$vendor" >"$stage/etc/easy-waf/easy-waf.env"
  printf '%s\n' "$payload" >"$stage/usr/share/easy-waf/payload-marker"
  chmod 0600 "$stage/etc/easy-waf/easy-waf.env"
  CONFFILE_TEST_DEB="$REPO_ROOT/dist/easy-waf_${version}_$(dpkg --print-architecture).deb"
  export CONFFILE_TEST_DEB
  dpkg-deb --build "$stage" "$CONFFILE_TEST_DEB" >/dev/null
  (cd "$REPO_ROOT/dist"; sha256sum ./*.deb | sed 's#  \./#  #' >SHA256SUMS)
  printf '%s\n' "$version" >"$REPO_ROOT/VERSION"
}
check_installed() {
  [[ "$(dpkg-query --admindir="$CONFFILE_TEST_ROOT/var/lib/dpkg" -W -f='${Status} ${Version}' easy-waf)" == "install ok installed $1" ]] || fail 'package not configured'
  [[ "$(cat "$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env")" == "$2" ]] || fail 'local conffile changed'
  [[ "$(stat -c %a "$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env")" == 600 ]] || fail 'conffile permissions changed'
}
build_deb 1.6.1 fixture-vendor-one
new_root adopted
printf 'fixture-local-operator-value\n' >"$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env"
chmod 0600 "$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env"
if ! install_release_package >"$ROOT/install.log" 2>&1 </dev/null; then
  tail -n 15 "$ROOT/install.log" >&2
  fail 'source conffile adoption failed without terminal'
fi
[[ "$EASY_WAF_PKG_INSTALLED" == 1 ]] || fail 'installer did not record package install'
check_installed 1.6.1 fixture-local-operator-value
build_deb 1.6.2 fixture-vendor-two
install_release_package >"$ROOT/install.log" 2>&1 </dev/null
check_installed 1.6.2 fixture-local-operator-value
[[ "$(cat "$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env.dpkg-dist")" == fixture-vendor-two ]] || fail 'new vendor default not retained separately'
build_deb 1.6.2 fixture-vendor-two fixture-rebuilt-payload
install_release_package >"$ROOT/reinstall.log" 2>&1 </dev/null
check_installed 1.6.2 fixture-local-operator-value
[[ "$(cat "$CONFFILE_TEST_ROOT/usr/share/easy-waf/payload-marker")" == fixture-rebuilt-payload ]] ||
  fail 'installer kept the previous payload after verifying a DEB with the same version'
new_root fresh
install_release_package >"$ROOT/install.log" 2>&1 </dev/null
check_installed 1.6.2 fixture-vendor-two

# A same-version repository package must not reach dpkg or configured hooks.
new_root conflicting_archive
build_deb 1.6.1 fixture-vendor-two fixture-initial-payload
install_release_package >"$ROOT/install.log" 2>&1 </dev/null
command mkdir "$CONFFILE_TEST_ROOT/repository"
build_deb 1.6.2 fixture-vendor-two fixture-repository-payload
repo_file="${CONFFILE_TEST_DEB##*/}"
mv "$CONFFILE_TEST_DEB" "$CONFFILE_TEST_ROOT/repository/$repo_file"
(
  cd "$CONFFILE_TEST_ROOT/repository"
  dpkg-deb -f "$repo_file"
  printf 'Filename: ./%s\nSize: %s\nSHA256: %s\n' "$repo_file" "$(stat -c %s "$repo_file")" "$(sha256sum <"$repo_file" | cut -d ' ' -f1)"
) >"$CONFFILE_TEST_ROOT/repository/Packages"
printf 'deb [trusted=yes] file:%s/repository ./\n' "$CONFFILE_TEST_ROOT" >"$CONFFILE_TEST_ROOT/sources.list"
printf 'DPkg::Pre-Install-Pkgs:: "touch %s/hook-ran";\n' "$CONFFILE_TEST_ROOT" >"$CONFFILE_TEST_ROOT/apt.conf"
apt-get -qq update >"$ROOT/index.log" 2>&1
build_deb 1.6.2 fixture-vendor-two fixture-verified-payload
if (CONFFILE_TEST_REPO_SELECTION=1 install_release_package) >"$ROOT/conflict.log" 2>&1 </dev/null; then
  fail 'installer accepted a repository DEB that differs from the verified file'
fi
if ! grep -Fq 'does not match the verified DEB' "$ROOT/conflict.log"; then
  tail -n 15 "$ROOT/conflict.log" >&2
  fail 'conflicting archive did not produce a verification diagnostic'
fi
[[ ! -e "$CONFFILE_TEST_ROOT/hook-ran" ]] || fail 'configured hook ran before archive verification'
[[ "$(cat "$CONFFILE_TEST_ROOT/usr/share/easy-waf/payload-marker")" == fixture-initial-payload ]] ||
  fail 'conflicting archive changed the installed payload'
: >"$CONFFILE_TEST_ROOT/sources.list"
install_release_package >"$ROOT/reinstall.log" 2>&1 </dev/null
[[ -e "$CONFFILE_TEST_ROOT/hook-ran" ]] || fail 'configured hook was discarded'
[[ "$(cat "$CONFFILE_TEST_ROOT/usr/share/easy-waf/payload-marker")" == fixture-verified-payload ]] ||
  fail 'reinstallation did not apply the verified payload'

# Simulate APT failing after dpkg has unpacked the verified package.
new_root partial
if (
  export CONFFILE_TEST_PARTIAL=1
  install_release_package || printf 'unpackaged fallback reached\n'
) >"$ROOT/partial.log" 2>&1 </dev/null; then
  fail 'installer continued after a partial package transaction'
fi
[[ "$(dpkg-query --admindir="$CONFFILE_TEST_ROOT/var/lib/dpkg" -W -f='${db:Status-Status}' easy-waf)" == unpacked ]] ||
  fail 'fixture did not leave an actual unpacked package'
grep -Fq 'APT failed to install the verified easy-waf package' "$ROOT/partial.log" ||
  fail 'partial package failure lacks an APT recovery diagnostic'

dpkg-query() { command dpkg-query --admindir="$CONFFILE_TEST_ROOT/var/lib/dpkg" "$@"; }
if easy_waf_require_unmanaged_install >"$ROOT/retry.log" 2>&1; then
  fail 'retry accepted an unpacked package on the unpackaged path'
fi
grep -Fq 'dpkg status: unpacked' "$ROOT/retry.log" || fail 'retry lacks package status'
CONFFILE_TEST_ROOT="$ROOT/fresh"
if easy_waf_require_unmanaged_install >"$ROOT/retry.log" 2>&1; then
  fail 'unpackaged path accepted the configured package'
fi
grep -Fq 'dpkg status: installed' "$ROOT/retry.log" || fail 'installed package lacks status'
"$DPKG_REAL" --root="$CONFFILE_TEST_ROOT" --log="$CONFFILE_TEST_ROOT/log/dpkg.log" --remove easy-waf >/dev/null
[[ "$(dpkg-query -W -f='${db:Status-Status}' easy-waf)" == config-files ]] ||
  fail 'fixture did not retain only conffiles'
easy_waf_require_unmanaged_install
new_root clean_unmanaged
easy_waf_require_unmanaged_install

new_root offline
sums="$REPO_ROOT/dist/SHA256SUMS"
mv "$sums" "$ROOT/original-sums"
if (EASY_WAF_OFFLINE=1 install_release_package) >"$ROOT/offline.log" 2>&1; then
  fail 'offline install accepted a missing manifest'
fi
[[ ! -e "$CONFFILE_TEST_CURL_CALLED" ]] || fail 'offline installation requested a remote manifest'
mv "$ROOT/original-sums" "$sums"
mv "$CONFFILE_TEST_DEB" "$ROOT/held.deb"
if (EASY_WAF_OFFLINE=1 install_release_package) >"$ROOT/offline.log" 2>&1; then
  fail 'offline install accepted a missing DEB'
fi
[[ ! -e "$CONFFILE_TEST_CURL_CALLED" ]] || fail 'offline installation requested a remote DEB'
mv "$ROOT/held.deb" "$CONFFILE_TEST_DEB"
cp "$sums" "$ROOT/original-sums"
printf '%064d  %s\n' 0 "${CONFFILE_TEST_DEB##*/}" >"$sums"
if (EASY_WAF_OFFLINE=1 EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 install_release_package) >"$ROOT/offline.log" 2>&1; then
  fail 'offline install accepted a corrupt manifest with the online override'
fi
[[ ! -s "$CONFFILE_TEST_ROOT/var/lib/dpkg/status" ]] || fail 'offline verification failure reached dpkg'
mv "$ROOT/original-sums" "$sums"
# The installer functions are loaded by eval.
# shellcheck disable=SC2317,SC2329
command() {
  if [[ "${1:-}" == -v && "${2:-}" == curl ]]; then return 1; fi
  builtin command "$@"
}
if command -v curl; then fail 'fixture did not hide curl'; fi
EASY_WAF_OFFLINE=1 install_release_package >"$ROOT/offline.log" 2>&1 </dev/null ||
  fail 'offline installation rejected a verified local DEB without curl'
unset -f command
check_installed 1.6.2 fixture-vendor-two
[[ ! -e "$CONFFILE_TEST_CURL_CALLED" ]] || fail 'verified local DEB used curl'

new_root spoa
printf 'fixture-spoa-operator-value\n' >"$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env"
chmod 0600 "$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env"
# Actual APT/dpkg still runs; only its package-selection input is local/dummy.
crowdsec_install_spoa_bouncer_package >"$ROOT/spoa.log" 2>&1 </dev/null
check_installed 1.6.2 fixture-spoa-operator-value
echo 'OK: real APT preserves conffiles, blocks partial fallback and installs the verified offline DEB without curl'
