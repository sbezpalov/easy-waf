#!/usr/bin/env bash
# Integrity verification for downloaded release artifacts.
# Sourced by scripts/install.sh and scripts/download-release.sh.
#
# Release binaries are installed to /usr/sbin as root, so TLS alone is not an
# acceptable integrity control: a typosquatted EASY_WAF_GITHUB_REPO, a poisoned
# release asset or a TLS-stripping proxy would mean root code execution.
# Every downloaded artifact is checked against SHA256SUMS published by
# .github/workflows/release.yml in the same release (fail-closed).
#
# Environment:
#   EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — downgrade verification failure to a
#       warning and keep the artifact (discouraged; for air-gapped mirrors that
#       do not publish SHA256SUMS).

log_relv() { echo "[easy-waf-release] $*"; }

# Hardened curl options: never downgrade to plain HTTP, not even through a redirect.
easy_waf_curl_https() {
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 "$@"
}

# easy_waf_sha256_file <path> — print the lowercase hex digest; rc=1 if no digest tool exists.
easy_waf_sha256_file() {
  local f="${1:?}"
  if command -v sha256sum &>/dev/null; then
    sha256sum "$f" 2>/dev/null | awk '{print tolower($1); exit}'
  elif command -v openssl &>/dev/null; then
    openssl dgst -sha256 "$f" 2>/dev/null | awk '{print tolower($NF); exit}'
  else
    return 1
  fi
}

# easy_waf_verify_sha256 <file> <expected-hex>
easy_waf_verify_sha256() {
  local file="${1:?}" expected="${2:?}" actual
  expected="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  actual="$(easy_waf_sha256_file "$file")" || {
    log_relv "no sha256sum/openssl available — cannot verify $file"
    return 1
  }
  if [[ -z "$actual" || "$actual" != "$expected" ]]; then
    log_relv "checksum MISMATCH for $(basename "$file")"
    log_relv "  expected: $expected"
    log_relv "  actual:   ${actual:-<none>}"
    return 1
  fi
  log_relv "sha256 verified: $(basename "$file")"
  return 0
}

# easy_waf_verify_release_artifact <file> <name-in-SHA256SUMS> <SHA256SUMS-url>
# Fail-closed: missing SHA256SUMS, missing entry or mismatch → non-zero.
easy_waf_verify_release_artifact() {
  local file="${1:?}" name="${2:?}" sums_url="${3:?}"
  local sums expected rc=0

  sums="$(mktemp)" || return 1

  if ! easy_waf_curl_https -o "$sums" "$sums_url" 2>/dev/null; then
    log_relv "SHA256SUMS not published at $sums_url"
    rc=1
  else
    # Accept both "<hash>  name" and "<hash> *name" (sha256sum binary mode).
    expected="$(awk -v n="$name" '{ f=$NF; sub(/^\*/,"",f); if (tolower(f)==tolower(n)) { print tolower($1); exit } }' "$sums")"
    if [[ -z "$expected" ]]; then
      log_relv "no SHA256SUMS entry for $name"
      rc=1
    else
      easy_waf_verify_sha256 "$file" "$expected" || rc=1
    fi
  fi
  rm -f "$sums"

  if [[ "$rc" -ne 0 ]]; then
    if [[ "${EASY_WAF_ALLOW_UNVERIFIED_RELEASE:-0}" == "1" ]]; then
      log_relv "WARNING: EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — installing an UNVERIFIED binary from $sums_url"
      return 0
    fi
    log_relv "refusing unverified release artifact (set EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 to override)"
  fi
  return "$rc"
}
