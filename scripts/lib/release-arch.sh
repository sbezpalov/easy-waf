#!/usr/bin/env bash
# Debian architecture name for release artifacts: amd64 or arm64.
# EASY_WAF_ARCH overrides detection. Unknown machines stay on amd64, which is
# what every release before arm64 assets existed was built for.

easy_waf_release_arch() {
  if [[ -n "${EASY_WAF_ARCH:-}" ]]; then
    printf '%s\n' "$EASY_WAF_ARCH"
    return 0
  fi
  local d=""
  if command -v dpkg >/dev/null 2>&1; then
    d="$(dpkg --print-architecture 2>/dev/null || true)"
  fi
  case "$d" in
    amd64|arm64)
      printf '%s\n' "$d"
      return 0
      ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) printf '%s\n' amd64 ;;
    aarch64|arm64) printf '%s\n' arm64 ;;
    *) printf '%s\n' amd64 ;;
  esac
}
