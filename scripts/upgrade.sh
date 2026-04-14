#!/usr/bin/env bash
set -euo pipefail
# Upgrade all control-plane binaries and restart units.
# Usage: sudo ./scripts/upgrade.sh /path/to/dist-or-tarball
#   Or:  sudo EASY_WAF_DIST_DIR=/opt/easy-waf-release ./scripts/install.sh (re-run install over same paths)

SRC="${1:?usage: upgrade.sh <directory-with-binaries-or-tarball>}"

if [[ -f "$SRC" && "$SRC" == *.tar.gz ]]; then
  TMP=$(mktemp -d)
  tar -xzf "$SRC" -C "$TMP"
  SRC="$TMP"
fi

export EASY_WAF_DIST_DIR="$SRC"
# Do not pull in PostgreSQL on upgrades unless explicitly requested (fresh install defaults to local PG).
export EASY_WAF_INSTALL_POSTGRES="${EASY_WAF_INSTALL_POSTGRES:-0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
bash "${SCRIPT_DIR}/install.sh"

systemctl restart easy-waf-api.service 2>/dev/null || true
systemctl restart easy-waf-acmed.service 2>/dev/null || true
echo "Restarted easy-waf-api and easy-waf-acmed (if units exist)"
