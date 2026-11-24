#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT
mkdir "$WORK/bin" "$WORK/assets"
export PATH="$WORK/bin:$PATH"
export GITHUB_REPOSITORY=easy-waf-fixture/release-fixture
export GH_LOG="$WORK/gh.log"

cat >"$WORK/bin/gh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" >>"$GH_LOG"
EOF
cat >"$WORK/bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 8 && $1 == verify-blob && $2 == --bundle && $3 == "$8.sigstore.json" ]]
[[ $4 == --certificate-oidc-issuer && $5 == https://token.actions.githubusercontent.com ]]
[[ $6 == --certificate-identity && $7 == "https://github.com/$GITHUB_REPOSITORY/.github/workflows/release.yml@refs/tags/$GITHUB_REF_NAME" ]]
[[ $(cat "$3") == "signed $8" ]]
EOF
cat >"$WORK/bin/xorriso" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 13 && $1 == -osirrox && $2 == on && $3 == -indev ]]
archive="$4"
shift 4
scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
while (( $# )); do
  [[ "$1" == -extract && "$2" == /* && "${2##*/}" == "${3##*/}" ]]
  tar -xf "$archive" -C "$scratch" "${2#/}"
  cp -a -- "$scratch/${2#/}" "$3"
  if [[ "$2" == /payload ]]; then
    printf '%s\n' "$3" >>"$GH_LOG.extracts"
    find "$3" -type d -exec chmod a-w {} +
  fi
  shift 3
done
EOF
chmod +x "$WORK/bin/gh" "$WORK/bin/cosign" "$WORK/bin/xorriso"

write_iso() {
  local iso="$1" deb="$2" tree location arch
  tree="$(mktemp -d "$WORK/iso-tree.XXXXXXXX")"
  arch="${deb##*_}"
  arch="${arch%.deb}"
  mkdir -p "$tree/repository" "$tree/payload/dist"
  for location in repository payload/dist; do
    cp -- "$deb" "$tree/$location/$deb"
  done
  if [[ -n "${ISO_PACKAGE_MISMATCH:-}" ]]; then
    printf 'different signed build\n' >>"$tree/$ISO_PACKAGE_MISMATCH/$deb"
  fi
  (cd "$tree/payload/dist" && sha256sum "$deb" >SHA256SUMS)
  printf '%s\n' "EASY_WAF_BUNDLE_VERSION=${ISO_BUNDLE_VERSION:-${GITHUB_REF_NAME#v}}" \
    "EASY_WAF_BUNDLE_UBUNTU=${ISO_BUNDLE_UBUNTU:-24.04}" "EASY_WAF_BUNDLE_ARCH=${ISO_BUNDLE_ARCH:-$arch}" \
    "EASY_WAF_BUNDLE_CROWDSEC=${ISO_BUNDLE_CROWDSEC:-1}" >"$tree/BUNDLE.env"
  case "${ISO_SNAPSHOT:-}" in
    directory) mkdir "$tree/payload/crowdsec-snapshot" ;;
    symlink) ln -s missing "$tree/payload/crowdsec-snapshot" ;;
  esac
  tar -cf "$iso" -C "$tree" "repository/$deb" payload BUNDLE.env
  sha256sum "$iso" >"$iso.sha256"
}

create_assets() {
  export GITHUB_REF_NAME="$1"
  local prefix="easy-waf_${1#v}" file
  packages=("${prefix}_linux_amd64.tar.gz" "${prefix}_amd64.deb" "${prefix}_linux_arm64.tar.gz" "${prefix}_arm64.deb")
  amd_iso="${prefix}_offline_ubuntu24.04_amd64.iso"
  arm_iso="${prefix}_offline_ubuntu24.04_arm64.iso"
  for file in "${packages[@]}"; do
    printf 'fixture for %s\n' "$file" >"$file"
  done
  sha256sum "${packages[@]}" >SHA256SUMS
  for file in SHA256SUMS "$amd_iso" "$arm_iso"; do
    printf 'signed %s\n' "$file" >"$file.sigstore.json"
  done
  write_iso "$amd_iso" "${packages[1]}"
  write_iso "$arm_iso" "${packages[3]}"
  printf 'release notes\n' >release_notes.md
  printf 'private fixture\n' >"${prefix}_offline_ubuntu24.04_amd64_private.iso"
  : >"$GH_LOG"
  : >"$GH_LOG.extracts"
}

expect_publication() {
  bash "$SCRIPT_DIR/publish-release.sh" "$WORK/assets"
  printf '%s\n' release create "$GITHUB_REF_NAME" "${packages[@]}" SHA256SUMS SHA256SUMS.sigstore.json \
    "$amd_iso" "$amd_iso.sha256" "$amd_iso.sigstore.json" "$arm_iso" "$arm_iso.sha256" "$arm_iso.sigstore.json" \
    --repo "$GITHUB_REPOSITORY" --verify-tag --title "$GITHUB_REF_NAME" --notes-file release_notes.md "$@" \
    >"$WORK/expected"
  diff -u "$WORK/expected" "$GH_LOG"
  local payload
  while IFS= read -r payload; do
    [[ ! -e "$payload" ]] || { echo 'FAIL: read-only ISO extraction was left behind' >&2; exit 1; }
  done <"$GH_LOG.extracts"
  echo "PASS: complete release $GITHUB_REF_NAME is submitted once"
}

reject() {
  local description="$1"
  if bash "$SCRIPT_DIR/publish-release.sh" "$WORK/assets" >"$WORK/error" 2>&1; then
    echo "FAIL: accepted $description" >&2
    exit 1
  fi
  if [[ -s "$GH_LOG" ]]; then
    echo "FAIL: invoked gh for $description" >&2
    exit 1
  fi
  if [[ $# -eq 2 ]]; then
    grep -Fq "$2" "$WORK/error" || { cat "$WORK/error" >&2; exit 1; }
  fi
  echo "PASS: $description blocks publication"
}

cd "$WORK/assets"
create_assets v1.6.1
expect_publication --latest=true
create_assets v1.7.0-rc.1
expect_publication --prerelease --latest=false
create_assets v1.7.0+build-ci
expect_publication --latest=true
create_assets v1.7.0-rc.1+build-ci
expect_publication --prerelease --latest=false

create_assets v1.6.1
rm -- "$arm_iso"
reject 'missing arm64 ISO'
create_assets v1.6.1
printf 'corrupt\n' >>"${packages[0]}"
reject 'package digest mismatch'
create_assets v1.6.1
sha256sum "${packages[@]:0:3}" >SHA256SUMS
reject 'signed manifest missing one package entry'
create_assets v1.6.1
printf 'corrupt\n' >>"$amd_iso"
reject 'amd64 ISO digest mismatch'
create_assets v1.6.1
printf 'invalid signature\n' >"$arm_iso.sigstore.json"
reject 'arm64 ISO signature failure'
create_assets v1.6.1
printf 'invalid signature\n' >SHA256SUMS.sigstore.json
reject 'package manifest signature failure'

for location in repository payload/dist; do
  create_assets v1.6.1
  ISO_PACKAGE_MISMATCH="$location" write_iso "$arm_iso" "${packages[3]}"
  reject "valid signature on a different ISO package ($location)"
  grep -Fq "$location/${packages[3]} does not match the verified release package" "$WORK/error"
done

create_assets v1.6.1
ISO_BUNDLE_ARCH=amd64 write_iso "$arm_iso" "${packages[3]}"
reject 'signed arm64 ISO with the wrong bundle architecture' 'unexpected public bundle metadata'
create_assets v1.6.1
ISO_BUNDLE_VERSION=1.6.0 write_iso "$arm_iso" "${packages[3]}"
reject 'signed ISO with the wrong bundle version' 'unexpected public bundle metadata'
create_assets v1.6.1
ISO_BUNDLE_UBUNTU=22.04 write_iso "$arm_iso" "${packages[3]}"
reject 'signed ISO with the wrong Ubuntu baseline' 'unexpected public bundle metadata'
create_assets v1.6.1
ISO_BUNDLE_CROWDSEC=0 write_iso "$arm_iso" "${packages[3]}"
reject 'signed ISO without the public CrowdSec profile' 'unexpected public bundle metadata'

snapshot_kinds=(directory)
if ln -s missing "$WORK/link-probe" 2>/dev/null && [[ -L "$WORK/link-probe" ]]; then
  snapshot_kinds+=(symlink)
fi
for kind in "${snapshot_kinds[@]}"; do
  create_assets v1.6.1
  ISO_SNAPSHOT="$kind" write_iso "$arm_iso" "${packages[3]}"
  reject "signed ISO with a CrowdSec snapshot $kind" 'embedded CrowdSec snapshot'
done
