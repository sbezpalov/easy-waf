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

bash "${TEMP_DIR}/install.sh" --verify-only >/dev/null
printf 'tampered\n' >>"${TEMP_DIR}/payload.txt"
if bash "${TEMP_DIR}/install.sh" --verify-only >/dev/null 2>&1; then
  echo "test-offline-bundle: tampered bundle was accepted" >&2
  exit 1
fi

# Regression: hashing must not list a temporary checksum file that disappears
# after rename. Writing SHA256SUMS.tmp inside the tree and then renaming it
# leaves a dangling SHA256SUMS.tmp entry that makes install --verify-only fail.
STAGE="${TEMP_DIR}/stage"
OUTSIDE="${TEMP_DIR}/outside"
mkdir -p "$STAGE" "$OUTSIDE"
printf 'payload\n' >"${STAGE}/payload.txt"
(
  cd "$STAGE"
  find . -type f ! -name SHA256SUMS -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum >"${OUTSIDE}/SHA256SUMS"
  mv "${OUTSIDE}/SHA256SUMS" SHA256SUMS
)
if grep -q 'SHA256SUMS\.tmp' "${STAGE}/SHA256SUMS"; then
  echo "test-offline-bundle: checksum list includes SHA256SUMS.tmp" >&2
  exit 1
fi
cp "${SCRIPT_DIR}/install-offline-bundle.sh" "${STAGE}/install.sh"
bash "${STAGE}/install.sh" --verify-only >/dev/null

echo "test-offline-bundle: PASS"
