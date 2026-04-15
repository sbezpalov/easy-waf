#!/usr/bin/env bash
# Start CrowdSec LAPI, register easy-waf-spoa / easy-waf-api bouncers, inject SPOA key, enable SPOA bouncer,
# write CROWDSEC_LAPI_* into /etc/easy-waf/easy-waf.env. Requires CrowdSec packages (see scripts/install.sh).
#
# Run as root after: sudo systemctl enable --now crowdsec.service (or let this re-invoke install.sh which starts LAPI when AUTO_START=1).
set -euo pipefail
[[ "$(id -u)" -eq 0 ]] || {
  echo "[easy-waf] must run as root" >&2
  exit 1
}
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export EASY_WAF_REPO_ROOT="${EASY_WAF_REPO_ROOT:-$ROOT}"
export EASY_WAF_INSTALL_CROWDSEC="${EASY_WAF_INSTALL_CROWDSEC:-1}"
export EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1
exec bash "$ROOT/scripts/install.sh"
