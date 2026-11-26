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
#   EASY_WAF_ALLOW_UNSIGNED_SUMS=1 — allow checksum-only verification for a
#       remote SHA256SUMS that cannot be authenticated with cosign.
#   EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — downgrade verification failure to a
#       warning and keep the artifact (discouraged; for air-gapped mirrors that
#       do not publish SHA256SUMS).

log_relv() { echo "[easy-waf-release] $*"; }

# Require HTTPS for every hop and bound stalled connections and transfers.
easy_waf_curl_https() {
  curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --connect-timeout 15 --speed-limit 1 --speed-time 60 "$@"
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

# easy_waf_verify_github_blob <file> <bundle> <owner/repo> <tag>
easy_waf_verify_github_blob() {
  local file="${1:?}" bundle="${2:?}" repo="${3:?}" tag="${4:?}"
  cosign verify-blob --bundle "$bundle" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "https://github.com/${repo}/.github/workflows/release.yml@refs/tags/${tag}" \
    "$file"
}

# easy_waf_verify_sums_signature <SHA256SUMS-file> <SHA256SUMS-url>
#
# SHA256SUMS sits next to what it describes, so it catches corruption but not a
# replaced release. .github/workflows/release.yml signs it with cosign, keyless:
# the signature names the workflow that made it. A local path is operator-owned
# input and is checksum-only. Remote sums fail closed unless they are a signed
# GitHub release or EASY_WAF_ALLOW_UNSIGNED_SUMS=1 explicitly permits the
# downgrade.
easy_waf_verify_sums_signature() {
  local sums="${1:?}" sums_url="${2:?}" bundle repo tag rc=0
  if [[ "$sums_url" == /* ]]; then
    log_relv "local SHA256SUMS — signature not checked"
    return 0
  fi
  if [[ ! "$sums_url" =~ ^https://github\.com/([^/?#]+/[^/?#]+)/releases/download/(v[^/?#]+)/SHA256SUMS$ ]]; then
    if [[ "${EASY_WAF_ALLOW_UNSIGNED_SUMS:-}" == "1" ]]; then
      log_relv "unversioned or non-GitHub SHA256SUMS — signature skipped (EASY_WAF_ALLOW_UNSIGNED_SUMS=1)"
      return 0
    fi
    log_relv "SHA256SUMS must use a versioned GitHub release URL (set EASY_WAF_ALLOW_UNSIGNED_SUMS=1 for checksum-only verification)"
    return 1
  fi
  repo="${BASH_REMATCH[1]}"
  tag="${BASH_REMATCH[2]}"
  if ! command -v cosign &>/dev/null; then
    if [[ "${EASY_WAF_ALLOW_UNSIGNED_SUMS:-}" == "1" ]]; then
      log_relv "cosign not installed — SHA256SUMS signature skipped (EASY_WAF_ALLOW_UNSIGNED_SUMS=1)"
      return 0
    fi
    log_relv "cosign not installed — refusing unsigned SHA256SUMS (install cosign or set EASY_WAF_ALLOW_UNSIGNED_SUMS=1)"
    return 1
  fi
  bundle="$(mktemp)" || return 1
  if ! easy_waf_curl_https -o "$bundle" "${sums_url}.sigstore.json" 2>/dev/null; then
    log_relv "no signature published at ${sums_url}.sigstore.json"
    rc=1
  elif ! easy_waf_verify_github_blob "$sums" "$bundle" "$repo" "$tag" >/dev/null 2>&1; then
    log_relv "SHA256SUMS signature INVALID for ${repo}"
    rc=1
  else
    log_relv "SHA256SUMS signature verified: ${repo}"
  fi
  rm -f "$bundle"
  return "$rc"
}

# easy_waf_verify_release_artifact <file> <name-in-SHA256SUMS> <SHA256SUMS-url-or-path> [digest-variable]
# Fail-closed: missing SHA256SUMS, missing entry or mismatch → non-zero.
# Third argument may be an https:// URL or an absolute local path (dist/SHA256SUMS).
easy_waf_verify_release_artifact() {
  local file="${1:?}" name="${2:?}" sums_url="${3:?}" digest_var="${4:-}"
  local sums expected rc=0 sums_tmp=0

  if [[ "$sums_url" == /* ]]; then
    sums="$sums_url"
    if [[ ! -f "$sums" ]]; then
      log_relv "local SHA256SUMS is missing: $sums"
      rc=1
    fi
  else
    sums="$(mktemp)" || return 1
    sums_tmp=1
    if ! easy_waf_curl_https -o "$sums" "$sums_url" 2>/dev/null; then
      log_relv "SHA256SUMS not published at $sums_url"
      rc=1
    fi
  fi

  if [[ "$rc" -eq 0 ]] && ! easy_waf_verify_sums_signature "$sums" "$sums_url"; then
    rc=1
  fi
  if [[ "$rc" -eq 0 ]]; then
    # Accept both "<hash>  name" and "<hash> *name" (sha256sum binary mode).
    # Linux artifact names are case-sensitive. Never choose a first match from
    # an ambiguous manifest or treat extra fields as part of a valid record.
    if ! expected="$(awk -v n="$name" '
      {
        f=$2; sub(/^\*/, "", f)
        if (f == n) {
          matches++
          if (NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-fA-F]+$/) bad=1
          digest=tolower($1)
        }
      }
      END {
        if (matches != 1 || bad) exit 1
        print digest
      }
    ' "$sums")"; then
      log_relv "SHA256SUMS must contain exactly one valid entry for $name"
      rc=1
    else
      easy_waf_verify_sha256 "$file" "$expected" || rc=1
    fi
  fi
  if [[ "$sums_tmp" -eq 1 ]]; then
    rm -f "$sums"
  fi

  if [[ "$rc" -ne 0 ]]; then
    if [[ "${EASY_WAF_ALLOW_UNVERIFIED_RELEASE:-0}" == "1" ]]; then
      log_relv "WARNING: EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 — installing an UNVERIFIED binary from $sums_url"
      if [[ -n "$digest_var" ]]; then
        expected="$(easy_waf_sha256_file "$file")" || return 1
      fi
      rc=0
    else
      log_relv "refusing unverified release artifact (set EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1 to override)"
    fi
  fi
  if [[ "$rc" -eq 0 && -n "$digest_var" ]]; then
    printf -v "$digest_var" '%s' "$expected"
  fi
  return "$rc"
}
