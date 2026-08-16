#!/usr/bin/env bash
# Resolve which GitHub repository release artifacts come from.
# Sourced by scripts/install.sh and scripts/download-release.sh.

# easy_waf_github_repo <repo-root> [explicit]
#
# Order: an explicit value wins; otherwise the origin remote of the checkout the
# script was run from; otherwise the upstream default.
#
# Deriving from the checkout matters: the hardcoded default is a placeholder, so
# on a fork (or after a rename) every release download 404s and the installer
# silently falls back to building from source — which also means the SHA256SUMS
# verification never actually runs. Reading the remote makes the installer fetch
# from the repository it was cloned from.
easy_waf_github_repo() {
  local repo_root="${1:-}" explicit="${2:-}"
  if [[ -n "$explicit" ]]; then
    printf '%s' "$explicit"
    return 0
  fi

  local url="" repo=""
  if [[ -n "$repo_root" ]] && command -v git &>/dev/null; then
    url="$(git -C "$repo_root" remote get-url origin 2>/dev/null || true)"
  fi
  case "$url" in
    *github.com*)
      repo="${url#*github.com}"
      repo="${repo#:}"
      repo="${repo#/}"
      repo="${repo%.git}"
      repo="${repo%/}"
      ;;
  esac
  # Accept only "owner/name"; anything else falls back to the default.
  if [[ ! "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
    repo=""
  fi
  printf '%s' "${repo:-easy-waf/easy-waf}"
}
