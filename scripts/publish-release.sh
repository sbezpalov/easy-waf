#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/release-verify.sh
source "$SCRIPT_DIR/lib/release-verify.sh"

repo="${GITHUB_REPOSITORY:?GitHub repository required}"
tag="${GITHUB_REF_NAME:?GitHub release tag required}"
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]]; then
  echo "ERROR: expected a version tag such as v1.6.1 or v1.7.0-rc.1" >&2
  exit 1
fi
version="${tag#v}"
cd -- "${1:?release asset directory required}"

packages=(
  "easy-waf_${version}_linux_amd64.tar.gz" "easy-waf_${version}_amd64.deb"
  "easy-waf_${version}_linux_arm64.tar.gz" "easy-waf_${version}_arm64.deb"
)
assets=("${packages[@]}" SHA256SUMS SHA256SUMS.sigstore.json)
for arch in amd64 arm64; do
  iso="easy-waf_${version}_offline_ubuntu24.04_${arch}.iso"
  assets+=("$iso" "$iso.sha256" "$iso.sigstore.json")
done
for file in "${assets[@]}" release_notes.md; do
  if [[ ! -f "$file" || ! -s "$file" ]]; then
    echo "ERROR: missing or empty release input: $file" >&2
    exit 1
  fi
done

easy_waf_verify_github_blob SHA256SUMS SHA256SUMS.sigstore.json "$repo" "$tag"
if ! sha256sum "${packages[@]}" | cmp -s - SHA256SUMS; then
  echo 'ERROR: SHA256SUMS does not match the four expected package assets' >&2
  exit 1
fi

verify_public_iso() (
  local iso="$1" deb="$2" arch="$3" work
  work="$(mktemp -d)"
  # Extracted ISO directories can be read-only.
  trap 'chmod -R u+w -- "$work" && rm -rf -- "$work"' EXIT
  mkdir "$work/repository"
  xorriso -osirrox on -indev "$iso" \
    -extract "/repository/$deb" "$work/repository/$deb" \
    -extract /payload "$work/payload" \
    -extract /BUNDLE.env "$work/BUNDLE.env"
  if ! printf '%s\n' "EASY_WAF_BUNDLE_VERSION=$version" EASY_WAF_BUNDLE_UBUNTU=24.04 \
    "EASY_WAF_BUNDLE_ARCH=$arch" EASY_WAF_BUNDLE_CROWDSEC=1 | cmp -s -- - "$work/BUNDLE.env"; then
    echo "ERROR: unexpected public bundle metadata in $iso" >&2
    exit 1
  fi
  if [[ -e "$work/payload/crowdsec-snapshot" || -L "$work/payload/crowdsec-snapshot" ]]; then
    echo "ERROR: embedded CrowdSec snapshot in $iso" >&2
    exit 1
  fi
  bash "$SCRIPT_DIR/verify-offline-release-package.sh" "$work" "$deb"
)

for arch in amd64 arm64; do
  iso="easy-waf_${version}_offline_ubuntu24.04_${arch}.iso"
  easy_waf_verify_github_blob "$iso" "$iso.sigstore.json" "$repo" "$tag"
  if ! sha256sum "$iso" | cmp -s - "$iso.sha256"; then
    echo "ERROR: checksum does not match $iso" >&2
    exit 1
  fi
  verify_public_iso "$iso" "easy-waf_${version}_${arch}.deb" "$arch"
done

release_flags=(--latest=true)
# A hyphen before build metadata marks a SemVer pre-release.
if [[ "${version%%+*}" == *-* ]]; then
  release_flags=(--prerelease --latest=false)
fi

# With assets, gh uploads to a draft before publishing it.
gh release create "$tag" "${assets[@]}" --repo "$repo" --verify-tag \
  --title "$tag" --notes-file release_notes.md "${release_flags[@]}"
