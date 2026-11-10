#!/usr/bin/env bash
# Install Easy Home WAF from a verified offline repository bundle.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [--verify-only]

Installs Easy Home WAF from this bundle on Ubuntu 24.04. --verify-only checks
the internal manifest without changing the host.
EOF
}

VERIFY_ONLY=0
case "${1:-}" in
  "") ;;
  --verify-only) VERIFY_ONLY=1 ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
[[ $# -le 1 ]] || {
  usage >&2
  exit 2
}

cd "$SCRIPT_DIR"
[[ -f SHA256SUMS ]] || {
  echo "[offline-install] SHA256SUMS is missing" >&2
  exit 1
}
echo "[offline-install] verifying bundle contents"
sha256sum -c --quiet SHA256SUMS || {
  echo "[offline-install] bundle verification failed; do not install it" >&2
  exit 1
}
if [[ "$VERIFY_ONLY" == "1" ]]; then
  echo "[offline-install] bundle contents verified"
  exit 0
fi

[[ "${EUID}" -eq 0 ]] || {
  echo "[offline-install] run as root: sudo bash install.sh" >&2
  exit 1
}
[[ -f BUNDLE.env ]] || {
  echo "[offline-install] verified BUNDLE.env is missing" >&2
  exit 1
}

bundle_value() {
  local key="$1"
  sed -n "s/^${key}=//p" BUNDLE.env | head -1
}

VERSION="$(bundle_value EASY_WAF_BUNDLE_VERSION)"
UBUNTU_VERSION="$(bundle_value EASY_WAF_BUNDLE_UBUNTU)"
ARCH="$(bundle_value EASY_WAF_BUNDLE_ARCH)"
CROWDSEC="$(bundle_value EASY_WAF_BUNDLE_CROWDSEC)"
[[ "$VERSION" =~ ^[0-9A-Za-z.+~-]+$ ]] || {
  echo "[offline-install] invalid bundle version" >&2
  exit 1
}
[[ "$UBUNTU_VERSION" == "24.04" ]] || {
  echo "[offline-install] unsupported bundle baseline: $UBUNTU_VERSION" >&2
  exit 1
}
[[ "$ARCH" == "amd64" || "$ARCH" == "arm64" ]] || {
  echo "[offline-install] unsupported bundle architecture: $ARCH" >&2
  exit 1
}
[[ "$CROWDSEC" == "0" || "$CROWDSEC" == "1" ]] || {
  echo "[offline-install] invalid CrowdSec profile: $CROWDSEC" >&2
  exit 1
}

# shellcheck source=/dev/null
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "$UBUNTU_VERSION" ]]; then
  echo "[offline-install] requires Ubuntu $UBUNTU_VERSION; found ${ID:-unknown} ${VERSION_ID:-unknown}" >&2
  exit 1
fi
HOST_ARCH="$(dpkg --print-architecture)"
if [[ "$HOST_ARCH" != "$ARCH" ]]; then
  echo "[offline-install] bundle is $ARCH but host is $HOST_ARCH" >&2
  exit 1
fi
[[ "$SCRIPT_DIR" != *[[:space:]]* ]] || {
  echo "[offline-install] mount/copy the bundle to a path without whitespace" >&2
  exit 1
}

mkdir -p /var/cache/apt/archives/partial
repo_kb="$(du -sk "$SCRIPT_DIR/repository" | awk '{print $1}')"
installed_kb="$(awk '/^Installed-Size:/ { total += $2 } END { print total + 0 }' "$SCRIPT_DIR/repository/Packages")"
cache_available_kb="$(df -Pk /var/cache/apt/archives | awk 'NR==2 {print $4}')"
root_available_kb="$(df -Pk / | awk 'NR==2 {print $4}')"
cache_required_kb="$((repo_kb + 262144))"
root_required_kb="$((installed_kb + 1048576))"
if (( cache_available_kb < cache_required_kb || root_available_kb < root_required_kb )); then
  echo "[offline-install] insufficient free space: cache needs ${cache_required_kb} KiB and root needs ${root_required_kb} KiB" >&2
  exit 1
fi

TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT
cat >"${TEMP_DIR}/sources.list" <<EOF
deb [trusted=yes] file:${SCRIPT_DIR}/repository ./
EOF
cat >"${TEMP_DIR}/apt.conf" <<EOF
Dir::Etc::sourcelist "${TEMP_DIR}/sources.list";
Dir::Etc::sourceparts "-";
Acquire::Languages "none";
APT::Get::List-Cleanup "0";
APT::Install-Recommends "false";
EOF

echo "[offline-install] using only the verified local repository"
export APT_CONFIG="${TEMP_DIR}/apt.conf"
export EASY_WAF_OFFLINE=1
export EASY_WAF_REPO_ROOT="${SCRIPT_DIR}/payload"
export EASY_WAF_RELEASE_VERSION="$VERSION"
export EASY_WAF_INSTALL_BUILD_DEPS=0
export EASY_WAF_BUILD_FROM_SOURCE=0
: "${EASY_WAF_INSTALL_CROWDSEC:=$CROWDSEC}"
export EASY_WAF_INSTALL_CROWDSEC
bash "${SCRIPT_DIR}/payload/scripts/install.sh"
