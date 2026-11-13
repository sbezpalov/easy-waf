#!/usr/bin/env bash
set -euo pipefail
# Upgrade all control-plane binaries and restart units.
# Usage: sudo ./scripts/upgrade.sh /path/to/dist-or-tarball
#   Or:  sudo EASY_WAF_DIST_DIR=/opt/easy-waf-release ./scripts/install.sh (re-run install over same paths)

SRC="${1:?usage: upgrade.sh <directory-with-binaries-or-tarball>}"

# Release tarballs nest binaries under dist/; install.sh flattens only on its
# download path. Hoist here so an operator-supplied tarball is used instead of
# silently falling through to a GitHub .deb fetch for VERSION.
flatten_release_dist() {
  local root="$1"
  if [[ -f "${root}/dist/easy-waf-api" ]]; then
    local b
    for b in easy-waf-hostd easy-waf-api easy-waf-acmed easy-wafd easy-waf-admin; do
      if [[ -f "${root}/dist/${b}" ]]; then
        mv -f "${root}/dist/${b}" "${root}/"
      fi
    done
    rmdir "${root}/dist" 2>/dev/null || true
  fi
  if [[ ! -f "${root}/easy-waf-api" ]]; then
    echo "ERROR: easy-waf-api not found under $root after unpack/flatten" >&2
    echo "Expected top-level binaries or nested dist/easy-waf-api from the release tarball." >&2
    exit 1
  fi
}

if [[ -f "$SRC" && "$SRC" == *.tar.gz ]]; then
  TMP=$(mktemp -d)
  tar -xzf "$SRC" -C "$TMP"
  # Tarball may contain a single top-level directory.
  if [[ ! -f "${TMP}/easy-waf-api" && ! -f "${TMP}/dist/easy-waf-api" ]]; then
    sub="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -1 || true)"
    if [[ -n "$sub" ]]; then
      TMP="$sub"
    fi
  fi
  SRC="$TMP"
fi

flatten_release_dist "$SRC"

export EASY_WAF_DIST_DIR="$SRC"
# Do not pull in PostgreSQL on upgrades unless explicitly requested (fresh install defaults to local PG).
export EASY_WAF_INSTALL_POSTGRES="${EASY_WAF_INSTALL_POSTGRES:-0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "${SCRIPT_DIR}/install.sh"

# This outer installer has finished its own package work. Use the same lock
# helper directly: do not cancel another maintenance service during its job.
/usr/sbin/easy-waf-hostd restart-after-packages || echo "WARNING: broker restart failed; inspect the error above before accepting this upgrade" >&2
systemctl try-restart --no-block easy-waf-api.service 2>/dev/null || true
systemctl try-restart --no-block easy-waf-acmed.service 2>/dev/null || true
echo "Requested package-safe broker restart; queued active API/ACME restarts"
