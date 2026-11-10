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

echo "test-offline-bundle: PASS"
