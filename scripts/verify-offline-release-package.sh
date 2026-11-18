#!/usr/bin/env bash
# Compare the extracted ISO's package copies with the verified release DEB.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/offline-apt.sh
. "${SCRIPT_DIR}/lib/offline-apt.sh"

if (( $# != 2 )); then
  echo 'Usage: bash verify-offline-release-package.sh EXTRACTED_ISO VERIFIED_DEB' >&2
  exit 2
fi

bundle="$1"
release_deb="$2"
name="${release_deb##*/}"

for location in payload/dist repository; do
  if ! cmp -s -- "$release_deb" "$bundle/$location/$name"; then
    echo "[offline-release] $location/$name does not match the verified release package" >&2
    exit 1
  fi
done

if ! offline_package_checksum_matches "$bundle/payload/dist" "$name"; then
  echo "[offline-release] payload checksum manifest does not match $name" >&2
  exit 1
fi

echo "[offline-release] both copies and the payload checksum match $name"
