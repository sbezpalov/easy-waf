#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-arch.sh
source "${SCRIPT_DIR}/lib/release-arch.sh"

[[ "$(EASY_WAF_ARCH=arm64 easy_waf_release_arch)" == "arm64" ]]
[[ "$(EASY_WAF_ARCH=amd64 easy_waf_release_arch)" == "amd64" ]]
echo "release-arch ok"
