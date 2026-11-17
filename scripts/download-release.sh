#!/usr/bin/env bash
# Download a release tarball from GitHub (or EASY_WAF_RELEASE_URL) and extract binaries into ./dist/
# Usage:
#   export EASY_WAF_VERSION=1.0.0
#   export GITHUB_REPOSITORY=org/easy-waf   # optional
#   bash scripts/download-release.sh
#
# If EASY_WAF_RELEASE_URL is set, it must contain dist/ or flat release binaries.
#
# Integrity: the GitHub path authenticates the release workflow's Sigstore bundle,
# then verifies the tarball against SHA256SUMS from the same release.
# For EASY_WAF_RELEASE_URL set EASY_WAF_RELEASE_SHA256=<hex> (or EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1).

set -euo pipefail

# A private mirror URL can carry credentials. Keep it out of tracing and
# remove it from the environment inherited by external commands.
initial_flags=$-
set +x
release_url="${EASY_WAF_RELEASE_URL:-}"
export -n release_url
unset EASY_WAF_RELEASE_URL
if [[ -z "$release_url" && "$initial_flags" == *x* ]]; then set -x; fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST="${REPO_ROOT}/dist"
mkdir -p "$DIST"

# shellcheck source=lib/release-verify.sh
source "${SCRIPT_DIR}/lib/release-verify.sh"
# shellcheck source=lib/release-unpack.sh
source "${SCRIPT_DIR}/lib/release-unpack.sh"

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

if [[ -n "$release_url" ]]; then
  if [[ "$release_url" == *[[:cntrl:]]* ]]; then
    log_relv "custom release URL contains control characters"
    exit 1
  fi
  echo "Downloading from the configured release URL"
  TGZ="${TMPD}/easy-waf-release.tgz"
  # Curl's quoted config values escape backslashes and quotes. Feeding the
  # option on stdin keeps the URL out of curl's process arguments.
  release_url="${release_url//\\/\\\\}"
  release_url="${release_url//\"/\\\"}"
  if ! printf 'url = "%s"\n' "$release_url" |
      easy_waf_curl_https --globoff -o "$TGZ" --config - >/dev/null 2>&1; then
    log_relv "download from the configured release URL failed"
    exit 1
  fi
  unset release_url
  if [[ -n "${EASY_WAF_RELEASE_SHA256:-}" ]]; then
    easy_waf_verify_sha256 "$TGZ" "$EASY_WAF_RELEASE_SHA256" || exit 1
  elif [[ "${EASY_WAF_ALLOW_UNVERIFIED_RELEASE:-0}" == "1" ]]; then
    log_relv "WARNING: EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — extracting an UNVERIFIED artifact"
  else
    log_relv "refusing unverified artifact: set EASY_WAF_RELEASE_SHA256=<hex> (or EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1)"
    exit 1
  fi
  easy_waf_unpack_release "$TGZ" "$DIST"
  echo "Extracted into $DIST"
  exit 0
fi

VERSION="${EASY_WAF_VERSION:?set EASY_WAF_VERSION or EASY_WAF_RELEASE_URL}"
# shellcheck source=lib/github-repo.sh
source "${SCRIPT_DIR}/lib/github-repo.sh"
GH="$(easy_waf_github_repo "$REPO_ROOT" "${GITHUB_REPOSITORY:-}")"
BASE="https://github.com/${GH}/releases/download/v${VERSION}"
# shellcheck source=lib/release-arch.sh
source "${SCRIPT_DIR}/lib/release-arch.sh"
ARCH="$(easy_waf_release_arch)"
NAME="easy-waf_${VERSION}_linux_${ARCH}.tar.gz"
URL="${BASE}/${NAME}"
TGZ="${TMPD}/${NAME}"

echo "Trying $URL"
easy_waf_curl_https -o "$TGZ" "$URL" || {
  echo "Release URL not found — build from source with 'make build' or publish release assets."
  exit 1
}
easy_waf_verify_release_artifact "$TGZ" "$NAME" "${BASE}/SHA256SUMS" || exit 1
easy_waf_unpack_release "$TGZ" "$DIST"
echo "Binaries in $DIST"
