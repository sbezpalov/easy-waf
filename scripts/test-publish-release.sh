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
chmod +x "$WORK/bin/gh" "$WORK/bin/cosign"

create_assets() {
  export GITHUB_REF_NAME="$1"
  local prefix="easy-waf_${1#v}" file
  packages=("${prefix}_linux_amd64.tar.gz" "${prefix}_amd64.deb" "${prefix}_linux_arm64.tar.gz" "${prefix}_arm64.deb")
  amd_iso="${prefix}_offline_ubuntu24.04_amd64.iso"
  arm_iso="${prefix}_offline_ubuntu24.04_arm64.iso"
  for file in "${packages[@]}" "$amd_iso" "$arm_iso"; do
    printf 'fixture for %s\n' "$file" >"$file"
  done
  sha256sum "${packages[@]}" >SHA256SUMS
  for file in SHA256SUMS "$amd_iso" "$arm_iso"; do
    printf 'signed %s\n' "$file" >"$file.sigstore.json"
  done
  sha256sum "$amd_iso" >"$amd_iso.sha256"
  sha256sum "$arm_iso" >"$arm_iso.sha256"
  printf 'release notes\n' >release_notes.md
  printf 'private fixture\n' >"${prefix}_offline_ubuntu24.04_amd64_private.iso"
  : >"$GH_LOG"
}

expect_publication() {
  bash "$SCRIPT_DIR/publish-release.sh" "$WORK/assets"
  printf '%s\n' release create "$GITHUB_REF_NAME" "${packages[@]}" SHA256SUMS SHA256SUMS.sigstore.json \
    "$amd_iso" "$amd_iso.sha256" "$amd_iso.sigstore.json" "$arm_iso" "$arm_iso.sha256" "$arm_iso.sigstore.json" \
    --repo "$GITHUB_REPOSITORY" --verify-tag --title "$GITHUB_REF_NAME" --notes-file release_notes.md "$@" \
    >"$WORK/expected"
  diff -u "$WORK/expected" "$GH_LOG"
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
