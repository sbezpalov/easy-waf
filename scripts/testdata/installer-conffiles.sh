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
export APT_REAL
command mkdir -p "$ROOT/bin" "$ROOT/repo/dist"
cat >"$ROOT/bin/apt-get" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" != update ]] || exit 0
args=()
for arg in "$@"; do
  if [[ "$arg" == crowdsec-haproxy-spoa-bouncer ]]; then arg="$CONFFILE_TEST_DEB"; fi
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
printf '#!/bin/sh\nexit 99\n' >"$ROOT/bin/curl"
chmod 0700 "$ROOT/bin/"*
export PATH="$ROOT/bin:$PATH"
REPO_ROOT="$ROOT/repo"
export EASY_WAF_PKG_MGR=apt
EASY_WAF_PKG_INSTALLED=0
log() { printf '%s\n' "$*"; }
die() { fail "$*"; }
easy_waf_apt_get_update() { :; }
for function_name in easy_waf_target_version install_release_package; do
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
}
build_deb() {
  local version="$1" vendor="$2" stage
  stage="$(mktemp -d "$ROOT/pkg.XXXXXX")"
  command mkdir -p "$stage/DEBIAN" "$stage/etc/easy-waf"
  printf 'Package: easy-waf\nVersion: %s\nArchitecture: %s\nMaintainer: Fixture <fixture@example.invalid>\nDescription: conffile test only\n' \
    "$version" "$(dpkg --print-architecture)" >"$stage/DEBIAN/control"
  printf '/etc/easy-waf/easy-waf.env\n' >"$stage/DEBIAN/conffiles"
  printf '%s\n' "$vendor" >"$stage/etc/easy-waf/easy-waf.env"
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
new_root fresh
install_release_package >"$ROOT/install.log" 2>&1 </dev/null
check_installed 1.6.2 fixture-vendor-two
new_root spoa
printf 'fixture-spoa-operator-value\n' >"$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env"
chmod 0600 "$CONFFILE_TEST_ROOT/etc/easy-waf/easy-waf.env"
# Actual APT/dpkg still runs; only its package-selection input is local/dummy.
crowdsec_install_spoa_bouncer_package >"$ROOT/spoa.log" 2>&1 </dev/null
check_installed 1.6.2 fixture-spoa-operator-value
echo 'OK: real APT preserves source/packaged conffiles, installs fresh defaults and adopts SPOA config unattended'
