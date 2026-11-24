#!/usr/bin/env bash
set -euo pipefail
# Upgrade all control-plane binaries and restart units.
# Usage: sudo ./scripts/upgrade.sh /path/to/dist-or-tarball
#   Or:  sudo EASY_WAF_DIST_DIR=/opt/easy-waf-release ./scripts/install.sh (re-run install over same paths)

SRC="${1:?usage: upgrade.sh <directory-with-binaries-or-tarball>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/os-pkg.sh
source "${SCRIPT_DIR}/lib/os-pkg.sh"
easy_waf_detect_pkg_mgr
easy_waf_require_unmanaged_install || exit 1

# shellcheck source=lib/release-unpack.sh
source "${SCRIPT_DIR}/lib/release-unpack.sh"

# An archive can wrap its flat/dist layout in one common directory. Detect the
# literal prefix without extracting any archive-supplied paths or links.
archive_prefix() {
  tar -tzf "$1" | awk '
    { name=$0; sub(/^\.\//,"",name)
      if (name=="" || name==".") next
      if (name=="easy-waf-api" || name=="dist/easy-waf-api") direct=1
      split(name,parts,"/"); root=parts[1]
      if (index(name,"/")==0 || root=="" || root=="." || root=="..") invalid=1
      if (first=="") first=root; else if (first!=root) invalid=1
    }
    END {
      if (direct) { print ""; exit }
      if (invalid || first=="") exit 1
      print first "/"
    }'
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
STAGED_DIST="$WORK_DIR/binaries"
# mktemp's private parent already protects the payload. Avoid a separate mode
# change here: Git Bash cannot apply it on some Windows temporary directories.
mkdir "$STAGED_DIST"

if [[ -f "$SRC" && "$SRC" == *.tar.gz ]]; then
  prefix="$(archive_prefix "$SRC")"
  easy_waf_unpack_release "$SRC" "$STAGED_DIST" "$prefix"
elif [[ -d "$SRC" ]]; then
  source_dir="$SRC"
  if [[ -f "$SRC/dist/easy-waf-api" ]]; then
    [[ ! -e "$SRC/easy-waf-api" ]] || { echo 'ERROR: ambiguous root and dist binaries' >&2; exit 1; }
    source_dir="$SRC/dist"
  fi
  for binary in easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin easy-wafd; do
    file="$source_dir/$binary"
    if [[ "$binary" == easy-wafd && ! -e "$file" && ! -L "$file" ]]; then continue; fi
    [[ -f "$file" && -s "$file" ]] || { echo "ERROR: missing or empty upgrade binary: $binary" >&2; exit 1; }
    cp -- "$file" "$STAGED_DIST/$binary"
    chmod 0755 "$STAGED_DIST/$binary"
  done
else
  echo 'ERROR: expected a binary directory or .tar.gz release archive' >&2
  exit 1
fi

export EASY_WAF_DIST_DIR="$STAGED_DIST"
# Do not pull in PostgreSQL on upgrades unless explicitly requested (fresh install defaults to local PG).
export EASY_WAF_INSTALL_POSTGRES="${EASY_WAF_INSTALL_POSTGRES:-0}"
bash "${SCRIPT_DIR}/install.sh"

# This outer installer has finished its own package work. Use the same lock
# helper directly: do not cancel another maintenance service during its job.
restart_failed=0
if ! /usr/sbin/easy-waf-hostd restart-after-packages; then
  echo 'ERROR: package-safe APT/broker restart failed' >&2
  restart_failed=1
fi
for unit in easy-waf-api.service easy-waf-acmed.service; do
  if ! systemctl try-restart --no-block "$unit"; then
    echo "ERROR: could not queue restart for $unit" >&2
    restart_failed=1
  fi
done
if (( restart_failed )); then
  echo 'ERROR: installer completed, but post-upgrade restart requests did not all succeed' >&2
  exit 1
fi
echo 'Requested package-safe APT/broker restart; systemd accepted active-only API/ACME restart requests'
echo 'Check service readiness and run appliance smoke checks to verify the upgrade.'
