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

curl_status=0
curl_args="$(
  curl() {
    printf '%s\n' "$@"
    return 28
  }
  easy_waf_curl_https -o "$TMPD/download" 'https://fixture.invalid/package.deb'
)" || curl_status=$?
[[ "$curl_status" == 28 ]] || fail 'release download swallowed the curl timeout'
expected_curl_args="$(printf '%s\n' -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --speed-limit 1 --speed-time 60 \
  -o "$TMPD/download" 'https://fixture.invalid/package.deb')"
[[ "$curl_args" == "$expected_curl_args" ]] || fail 'release download must bound connection and transfer stalls'

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
# 5a. local absolute SHA256SUMS path (dist/ offline / local .deb installs)
if ! easy_waf_verify_release_artifact "$ART" "$NAME" "$SUMS" >/dev/null 2>&1; then
  fail "local SHA256SUMS path rejected a matching artifact"
fi

# Exercise the real verifier, not a second copy of its manifest parser.
for layout in text binary; do
  marker=''
  [[ "$layout" != binary ]] || marker='*'
  printf '%s  %s%s\n' "$(printf '%s' "$DIGEST" | tr '[:lower:]' '[:upper:]')" "$marker" "$NAME" >"$SUMS"
  easy_waf_verify_release_artifact "$ART" "$NAME" "$SUMS" >/dev/null || fail "$layout manifest rejected"
done
for malformed in duplicate conflicting extra-field casefold short-digest; do
  case "$malformed" in
    duplicate) printf '%s  %s\n%s  %s\n' "$DIGEST" "$NAME" "$DIGEST" "$NAME" >"$SUMS" ;;
    conflicting) printf '%s  %s\n%s  %s\n' "$DIGEST" "$NAME" "$(printf '0%.0s' {1..64})" "$NAME" >"$SUMS" ;;
    extra-field) printf '%s extra %s\n' "$DIGEST" "$NAME" >"$SUMS" ;;
    casefold) printf '%s  %s\n' "$DIGEST" "$(printf '%s' "$NAME" | tr '[:lower:]' '[:upper:]')" >"$SUMS" ;;
    short-digest) printf 'abcd  %s\n' "$NAME" >"$SUMS" ;;
  esac
  if easy_waf_verify_release_artifact "$ART" "$NAME" "$SUMS" >/dev/null 2>&1; then
    fail "$malformed manifest accepted"
  fi
done
printf '%s  %s\n' "$DIGEST" "$NAME" >"$SUMS"
# 5b. fail-closed when SHA256SUMS cannot be fetched
if easy_waf_verify_release_artifact "$ART" "$NAME" "https://127.0.0.1:1/SHA256SUMS" >/dev/null 2>&1; then
  fail "missing SHA256SUMS accepted (must fail closed)"
fi

# 5c. a fetched non-GitHub SHA256SUMS is not trusted without an explicit override
if easy_waf_verify_sums_signature "$SUMS" "https://mirror.example/SHA256SUMS" >/dev/null 2>&1; then
  fail "unsigned non-GitHub SHA256SUMS accepted"
fi
EASY_WAF_ALLOW_UNSIGNED_SUMS=1 \
  easy_waf_verify_sums_signature "$SUMS" "https://mirror.example/SHA256SUMS" >/dev/null ||
  fail "EASY_WAF_ALLOW_UNSIGNED_SUMS=1 did not allow a checksum-only mirror"

# 6. explicit override still allows it
if ! EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 easy_waf_verify_release_artifact \
  "$ART" "$NAME" "https://127.0.0.1:1/SHA256SUMS" >/dev/null 2>&1; then
  fail "EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 did not override"
fi

# Signature check, with a stand-in cosign and bundle download.
GH_URL="https://github.com/acme/easy-waf/releases/download/v9.9.9/SHA256SUMS"
easy_waf_curl_https() { # -o <file> <url>
  : >"${TMPD}/curl.called"
  [[ "${FAKE_BUNDLE:-1}" == "1" ]] && : >"$2"
}
mkdir -p "${TMPD}/bin"
cat >"${TMPD}/bin/cosign" <<'FAKE'
#!/bin/sh
printf '%s\n' "$@" >"$FAKE_ARGS"
exit "$FAKE_RC"
FAKE
chmod +x "${TMPD}/bin/cosign"
export FAKE_ARGS="${TMPD}/args"
export FAKE_RC=0
SUMS="${TMPD}/sums"
: >"$SUMS"

EMPTY_PATH="${TMPD}/nothing"
mkdir -p "$EMPTY_PATH"
if PATH="$EMPTY_PATH" easy_waf_verify_sums_signature "$SUMS" "$GH_URL" >/dev/null; then
  fail "GitHub release accepted without cosign"
fi
PATH="$EMPTY_PATH" EASY_WAF_ALLOW_UNSIGNED_SUMS=1 \
  easy_waf_verify_sums_signature "$SUMS" "$GH_URL" >/dev/null ||
  fail "EASY_WAF_ALLOW_UNSIGNED_SUMS=1 did not allow checksum-only verification"
PATH="${TMPD}/bin:$PATH" FAKE_RC=0 easy_waf_verify_sums_signature "$SUMS" "$GH_URL" >/dev/null \
  || fail "valid signature rejected"
grep -qxF -- '--certificate-identity' "$FAKE_ARGS" \
  || fail "signature must use exact identity rather than an unbounded tag regexp"
grep -qxF 'https://token.actions.githubusercontent.com' "$FAKE_ARGS" \
  || fail "signature must name the GitHub Actions OIDC issuer"
grep -qxF 'https://github.com/acme/easy-waf/.github/workflows/release.yml@refs/tags/v9.9.9' "$FAKE_ARGS" \
  || fail "signature not tied to the requested release tag"
PATH="${TMPD}/bin:$PATH" FAKE_RC=0 easy_waf_verify_sums_signature \
  "$SUMS" 'https://github.com/acme/easy-waf/releases/download/v9.9.8/SHA256SUMS' >/dev/null \
  || fail "second valid versioned signature rejected"
grep -qxF 'https://github.com/acme/easy-waf/.github/workflows/release.yml@refs/tags/v9.9.8' "$FAKE_ARGS" \
  || fail "different release did not change the expected signing identity"
if PATH="${TMPD}/bin:$PATH" FAKE_RC=0 easy_waf_verify_sums_signature \
  "$SUMS" 'https://github.com/acme/easy-waf/releases/latest/download/SHA256SUMS' >/dev/null; then
  fail "unversioned URL accepted without an explicit unsigned override"
fi
if PATH="${TMPD}/bin:$PATH" FAKE_RC=1 easy_waf_verify_sums_signature "$SUMS" "$GH_URL" >/dev/null; then
  fail "invalid signature accepted"
fi
if PATH="${TMPD}/bin:$PATH" FAKE_RC=0 FAKE_BUNDLE=0 easy_waf_verify_sums_signature "$SUMS" "$GH_URL" >/dev/null; then
  fail "missing signature accepted with cosign installed"
fi

rm -f "${TMPD}/curl.called"
if easy_waf_verify_release_artifact "$ART" "$NAME" "${TMPD}/missing-local-sums" >/dev/null; then
  fail "missing local manifest accepted"
fi
[[ ! -e "${TMPD}/curl.called" ]] || fail "missing local manifest attempted a curl transfer"

echo "OK: release-verify checks passed"
