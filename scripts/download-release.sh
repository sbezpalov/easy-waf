#!/usr/bin/env bash
# Download a release tarball from GitHub (or EASY_WAF_RELEASE_URL) and extract binaries into ./dist/
# Usage:
#   export EASY_WAF_VERSION=1.0.0
#   export GITHUB_REPOSITORY=org/easy-waf   # optional
#   bash scripts/download-release.sh
#
# If EASY_WAF_RELEASE_URL is set, it is used directly (must point to a .tar.gz with dist/ or linux-amd64 binaries).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="${REPO_ROOT}/dist"
mkdir -p "$DIST"

if [[ -n "${EASY_WAF_RELEASE_URL:-}" ]]; then
  echo "Downloading $EASY_WAF_RELEASE_URL"
  curl -fsSL -o /tmp/easy-waf-release.tgz "$EASY_WAF_RELEASE_URL"
  tar -xzf /tmp/easy-waf-release.tgz -C "$DIST" --strip-components=0 2>/dev/null || tar -xzf /tmp/easy-waf-release.tgz -C "$DIST"
  if [[ -f "${DIST}/dist/easy-waf-api" ]]; then
    for b in easy-waf-api easy-waf-acmed easy-wafd easy-waf-admin; do
      [[ -f "${DIST}/dist/${b}" ]] && mv -f "${DIST}/dist/${b}" "${DIST}/"
    done
    rmdir "${DIST}/dist" 2>/dev/null || true
  fi
  echo "Extracted into $DIST"
  exit 0
fi

VERSION="${EASY_WAF_VERSION:?set EASY_WAF_VERSION or EASY_WAF_RELEASE_URL}"
GH="${GITHUB_REPOSITORY:-easy-waf/easy-waf}"
URL="https://github.com/${GH}/releases/download/v${VERSION}/easy-waf_${VERSION}_linux_amd64.tar.gz"

echo "Trying $URL"
curl -fsSL -o /tmp/easy-waf.tgz "$URL" || {
  echo "Release URL not found — build from source with 'make build' or publish release assets."
  exit 1
}
tar -xzf /tmp/easy-waf.tgz -C "$DIST"
if [[ -f "${DIST}/dist/easy-waf-api" ]]; then
  for b in easy-waf-api easy-waf-acmed easy-wafd easy-waf-admin; do
    [[ -f "${DIST}/dist/${b}" ]] && mv -f "${DIST}/dist/${b}" "${DIST}/"
  done
  rmdir "${DIST}/dist" 2>/dev/null || true
fi
echo "Binaries in $DIST"
