#!/usr/bin/env bash
# Download a release tarball from GitHub (or EASY_WAF_RELEASE_URL) and extract binaries into ./dist/
# Usage:
#   export EASY_WAF_VERSION=1.0.0
#   export GITHUB_REPOSITORY=org/easy-waf   # optional
#   bash scripts/download-release.sh
#
# If EASY_WAF_RELEASE_URL is set, it is used directly (must point to a .tar.gz with dist/ or linux-amd64 binaries).
#
# Integrity: the GitHub path verifies the tarball against SHA256SUMS from the same release.
# For EASY_WAF_RELEASE_URL set EASY_WAF_RELEASE_SHA256=<hex> (or EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST="${REPO_ROOT}/dist"
mkdir -p "$DIST"

# shellcheck source=lib/release-verify.sh
source "${SCRIPT_DIR}/lib/release-verify.sh"

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

promote_binaries() {
  if [[ -f "${DIST}/dist/easy-waf-api" ]]; then
    for b in easy-waf-hostd easy-waf-api easy-waf-acmed easy-wafd easy-waf-admin; do
      [[ -f "${DIST}/dist/${b}" ]] && mv -f "${DIST}/dist/${b}" "${DIST}/"
    done
    rmdir "${DIST}/dist" 2>/dev/null || true
  fi
}

if [[ -n "${EASY_WAF_RELEASE_URL:-}" ]]; then
  echo "Downloading $EASY_WAF_RELEASE_URL"
  TGZ="${TMPD}/easy-waf-release.tgz"
  easy_waf_curl_https -o "$TGZ" "$EASY_WAF_RELEASE_URL"
  if [[ -n "${EASY_WAF_RELEASE_SHA256:-}" ]]; then
    easy_waf_verify_sha256 "$TGZ" "$EASY_WAF_RELEASE_SHA256" || exit 1
  elif [[ "${EASY_WAF_ALLOW_UNVERIFIED_RELEASE:-0}" == "1" ]]; then
    log_relv "WARNING: EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — extracting an UNVERIFIED artifact"
  else
    log_relv "refusing unverified artifact: set EASY_WAF_RELEASE_SHA256=<hex> (or EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1)"
    exit 1
  fi
  tar -xzf "$TGZ" -C "$DIST" --strip-components=0 2>/dev/null || tar -xzf "$TGZ" -C "$DIST"
  promote_binaries
  echo "Extracted into $DIST"
  exit 0
fi

VERSION="${EASY_WAF_VERSION:?set EASY_WAF_VERSION or EASY_WAF_RELEASE_URL}"
# shellcheck source=lib/github-repo.sh
source "${SCRIPT_DIR}/lib/github-repo.sh"
GH="$(easy_waf_github_repo "$REPO_ROOT" "${GITHUB_REPOSITORY:-}")"
BASE="https://github.com/${GH}/releases/download/v${VERSION}"
NAME="easy-waf_${VERSION}_linux_amd64.tar.gz"
URL="${BASE}/${NAME}"
TGZ="${TMPD}/${NAME}"

echo "Trying $URL"
easy_waf_curl_https -o "$TGZ" "$URL" || {
  echo "Release URL not found — build from source with 'make build' or publish release assets."
  exit 1
}
easy_waf_verify_release_artifact "$TGZ" "$NAME" "${BASE}/SHA256SUMS" || exit 1
tar -xzf "$TGZ" -C "$DIST"
promote_binaries
echo "Binaries in $DIST"
