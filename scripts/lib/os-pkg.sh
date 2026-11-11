#!/usr/bin/env bash
# Package manager helpers: Ubuntu (apt) only.
# Sourced by scripts/install.sh after SCRIPT_DIR is known.

easy_waf_detect_pkg_mgr() {
  if command -v apt-get &>/dev/null; then
    export EASY_WAF_PKG_MGR=apt
  else
    export EASY_WAF_PKG_MGR=
  fi
}

easy_waf_pkg_installed() {
  local p="$1"
  case "${EASY_WAF_PKG_MGR:-}" in
    apt) dpkg -s "$p" &>/dev/null 2>&1 ;;
    *) return 1 ;;
  esac
}

# Minimum Go major.minor (e.g. 1 22) for this repo (see go.mod).
easy_waf_go_version_meets() {
  local want_maj="$1"
  local want_min="$2"
  command -v go &>/dev/null || return 1
  local raw gv maj min rest
  raw="$(go env GOVERSION 2>/dev/null || true)"
  [[ -n "$raw" ]] || raw="$(go version 2>/dev/null | awk '{print $3}')"
  gv="${raw#go}"
  gv="${gv%%-*}"
  maj="${gv%%.*}"
  rest="${gv#*.}"
  min="${rest%%.*}"
  [[ "$maj" =~ ^[0-9]+$ ]] && [[ "$min" =~ ^[0-9]+$ ]] || return 1
  if [[ "$maj" -gt "$want_maj" ]]; then
    return 0
  fi
  if [[ "$maj" -eq "$want_maj" ]] && [[ "$min" -ge "$want_min" ]]; then
    return 0
  fi
  return 1
}

# Idempotent apt-get update for this shell (install.sh runs once).
easy_waf_apt_get_update() {
  [[ "${EASY_WAF_PKG_MGR:-}" == "apt" ]] || return 0
  if [[ "${EASY_WAF_APT_UPDATED:-0}" == "1" ]]; then
    return 0
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  export EASY_WAF_APT_UPDATED=1
}

# Install upstream Go toolchain to /usr/local/go when distro packages are too old.
easy_waf_bootstrap_go_toolchain() {
  # A different version needs its checksum too: EASY_WAF_BOOTSTRAP_GO_SHA256 (go.dev/dl).
  local ver="${EASY_WAF_BOOTSTRAP_GO_VERSION:-1.27.4}"
  local arch raw_arch sha256 tarball
  raw_arch="$(uname -m)"
  case "$raw_arch" in
    x86_64) arch=amd64 ;;
    aarch64) arch=arm64 ;;
    arm64) arch=arm64 ;;
    *)
      echo "[easy-waf] ERROR: unsupported machine for Go bootstrap: $raw_arch" >&2
      return 1
      ;;
  esac
  command -v curl &>/dev/null || {
    echo "[easy-waf] ERROR: curl required to bootstrap Go" >&2
    return 1
  }
  sha256="${EASY_WAF_BOOTSTRAP_GO_SHA256:-}"
  if [[ -z "$sha256" && "$ver" == "1.27.4" ]]; then
    case "$arch" in
      amd64) sha256=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 ;;
      arm64) sha256=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92 ;;
    esac
  fi
  if [[ -z "$sha256" ]]; then
    echo "[easy-waf] ERROR: Go ${ver} needs EASY_WAF_BOOTSTRAP_GO_SHA256 (see go.dev/dl)" >&2
    return 1
  fi
  local url="https://go.dev/dl/go${ver}.linux-${arch}.tar.gz"
  echo "[easy-waf] Downloading Go ${ver} (${arch}) from go.dev..."
  tarball="$(mktemp)"
  curl -fsSL -o "$tarball" "$url" || {
    rm -f "$tarball"
    return 1
  }
  if ! printf '%s  %s\n' "$sha256" "$tarball" | sha256sum -c --status; then
    echo "[easy-waf] ERROR: checksum mismatch for $url" >&2
    rm -f "$tarball"
    return 1
  fi
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "$tarball"
  rm -f "$tarball"
  export PATH="/usr/local/go/bin:${PATH}"
}
