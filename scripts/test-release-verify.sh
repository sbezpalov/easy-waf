#!/usr/bin/env bash
# Offline checks for scripts/lib/release-verify.sh (no network).
# Run: bash scripts/test-release-verify.sh   (also part of `make verify`)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/release-verify.sh
source "${SCRIPT_DIR}/lib/release-verify.sh"

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

ART="${TMPD}/easy-waf_9.9.9_linux_amd64.tar.gz"
printf 'easy-waf release payload\n' >"$ART"
NAME="$(basename "$ART")"

DIGEST="$(easy_waf_sha256_file "$ART")"
[[ -n "$DIGEST" ]] || fail "easy_waf_sha256_file returned nothing"
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || fail "digest is not 64 hex chars: $DIGEST"

# 1. matching digest passes, uppercase and surrounding whitespace tolerated
easy_waf_verify_sha256 "$ART" "$DIGEST" >/dev/null || fail "matching digest rejected"
easy_waf_verify_sha256 "$ART" "  $(printf '%s' "$DIGEST" | tr '[:lower:]' '[:upper:]')  " >/dev/null ||
  fail "uppercase/padded digest rejected"

# 2. wrong digest is rejected
if easy_waf_verify_sha256 "$ART" "$(printf '0%.0s' {1..64})" >/dev/null 2>&1; then
  fail "wrong digest accepted"
fi

# 3. tampered artifact is rejected against the original digest
cp "$ART" "${TMPD}/tampered.tgz"
printf 'backdoor\n' >>"${TMPD}/tampered.tgz"
if easy_waf_verify_sha256 "${TMPD}/tampered.tgz" "$DIGEST" >/dev/null 2>&1; then
  fail "tampered artifact accepted"
fi

# 4. SHA256SUMS parsing: both "hash  name" and "hash *name" layouts, entry picked by name
SUMS="${TMPD}/SHA256SUMS"
{
  printf '%s  other-artifact.tar.gz\n' "$(printf 'a%.0s' {1..64})"
  printf '%s *%s\n' "$DIGEST" "$NAME"
} >"$SUMS"
parsed="$(awk -v n="$NAME" '{ f=$NF; sub(/^\*/,"",f); if (tolower(f)==tolower(n)) { print tolower($1); exit } }' "$SUMS")"
[[ "$parsed" == "$DIGEST" ]] || fail "SHA256SUMS parsing picked '$parsed' instead of '$DIGEST'"

# 5. fail-closed when SHA256SUMS cannot be fetched (file:// URL that does not exist)
if easy_waf_verify_release_artifact "$ART" "$NAME" "https://127.0.0.1:1/SHA256SUMS" >/dev/null 2>&1; then
  fail "missing SHA256SUMS accepted (must fail closed)"
fi

# 6. explicit override still allows it
if ! EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 easy_waf_verify_release_artifact \
  "$ART" "$NAME" "https://127.0.0.1:1/SHA256SUMS" >/dev/null 2>&1; then
  fail "EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 did not override"
fi

echo "OK: release-verify checks passed"
