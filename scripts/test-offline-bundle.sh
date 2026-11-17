#!/usr/bin/env bash
# Smoke-test offline bundle integrity verification without root or host changes.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

cp "${SCRIPT_DIR}/install-offline-bundle.sh" "${TEMP_DIR}/install.sh"
printf 'test payload\n' >"${TEMP_DIR}/payload.txt"
(
  cd "$TEMP_DIR"
  sha256sum install.sh payload.txt >SHA256SUMS
)

"${BASH}" "${TEMP_DIR}/install.sh" --verify-only >/dev/null
printf 'tampered\n' >>"${TEMP_DIR}/payload.txt"
if "${BASH}" "${TEMP_DIR}/install.sh" --verify-only >/dev/null 2>&1; then
  echo "test-offline-bundle: tampered bundle was accepted" >&2
  exit 1
fi

# Use the actual builder's checksum step. The nested manifest must be verified
# by the outer one, and the outer manifest cannot list a temporary self-entry.
STAGE="${TEMP_DIR}/stage"
PAYLOAD="${STAGE}/payload"
WORK_DIR="${TEMP_DIR}/outside"
mkdir -p "$PAYLOAD/dist" "$WORK_DIR"
VERSION=9.9.9
ARCH=amd64
printf 'payload\n' >"${STAGE}/payload.txt"
printf 'fixture package\n' >"$PAYLOAD/dist/easy-waf_${VERSION}_${ARCH}.deb"
cp "${SCRIPT_DIR}/install-offline-bundle.sh" "${STAGE}/install.sh"
checksum_step="$(sed -n '/^write_bundle_checksums() {$/,/^}$/p' "$SCRIPT_DIR/build-offline-bundle.sh")"
[[ -n "$checksum_step" ]] || { echo 'test-offline-bundle: builder checksum step missing' >&2; exit 1; }
eval "$checksum_step"
write_bundle_checksums
(cd "$PAYLOAD/dist" && sha256sum -c --quiet SHA256SUMS)
grep -qF '  ./payload/dist/SHA256SUMS' "${STAGE}/SHA256SUMS"
if grep -q 'SHA256SUMS\.tmp' "${STAGE}/SHA256SUMS"; then
  echo "test-offline-bundle: checksum list includes SHA256SUMS.tmp" >&2
  exit 1
fi
"${BASH}" "${STAGE}/install.sh" --verify-only >/dev/null
printf '\n' >>"$PAYLOAD/dist/SHA256SUMS"
if "${BASH}" "${STAGE}/install.sh" --verify-only >/dev/null 2>&1; then
  echo 'test-offline-bundle: modified package manifest was accepted' >&2
  exit 1
fi

echo "test-offline-bundle: PASS"
