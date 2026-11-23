#!/usr/bin/env bash
# Install Easy Home WAF from a verified offline repository bundle.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [--verify-only]

Installs Easy Home WAF from this bundle on Ubuntu 24.04. --verify-only checks
the internal manifest without changing the host.

Set EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR to a trusted, prepared snapshot
directory when installing CrowdSec from an ISO without an embedded snapshot.
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

operator_snapshot="${EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR:-}"
if [[ -n "$operator_snapshot" && "$operator_snapshot" != /* ]]; then
  operator_snapshot="$PWD/$operator_snapshot"
fi
cd "$SCRIPT_DIR"
[[ -f SHA256SUMS ]] || {
  echo "[offline-install] SHA256SUMS is missing" >&2
  exit 1
}
echo "[offline-install] verifying bundle contents"
sha256sum -c --strict --quiet SHA256SUMS || {
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

BUNDLE_VERSION="$(bundle_value EASY_WAF_BUNDLE_VERSION)"
UBUNTU_VERSION="$(bundle_value EASY_WAF_BUNDLE_UBUNTU)"
ARCH="$(bundle_value EASY_WAF_BUNDLE_ARCH)"
CROWDSEC="$(bundle_value EASY_WAF_BUNDLE_CROWDSEC)"
[[ "$BUNDLE_VERSION" =~ ^[0-9A-Za-z.+~-]+$ ]] || {
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
# shellcheck source=lib/offline-apt.sh
. "${SCRIPT_DIR}/payload/scripts/lib/offline-apt.sh"

package_name="easy-waf_${BUNDLE_VERSION}_${ARCH}.deb"
payload_dist="${SCRIPT_DIR}/payload/dist"
if ! offline_package_checksum_matches "$payload_dist" "$package_name"; then
  echo "[offline-install] payload checksum manifest does not match $package_name" >&2
  exit 1
fi
offline_check_package_identity "$payload_dist/$package_name" "$BUNDLE_VERSION" "$ARCH"
if ! cmp -s -- "$payload_dist/$package_name" "$SCRIPT_DIR/repository/$package_name"; then
  echo "[offline-install] repository/$package_name does not match the verified installer payload" >&2
  exit 1
fi

: "${EASY_WAF_INSTALL_CROWDSEC:=$CROWDSEC}"
case "$EASY_WAF_INSTALL_CROWDSEC" in
  0|1) ;;
  *) echo "[offline-install] EASY_WAF_INSTALL_CROWDSEC must be 0 or 1" >&2; exit 1 ;;
esac
unset EASY_WAF_OFFLINE_CROWDSEC_PREPARED
embedded_snapshot="$SCRIPT_DIR/payload/crowdsec-snapshot"
snapshot="$operator_snapshot"
if [[ -n "$operator_snapshot" ]]; then
  if [[ "$EASY_WAF_INSTALL_CROWDSEC" != 1 ]]; then
    echo "[offline-install] a supplied snapshot requires CrowdSec provisioning" >&2
    exit 1
  fi
  if [[ -e "$embedded_snapshot" || -L "$embedded_snapshot" ]]; then
    echo "[offline-install] the bundle already has an embedded CrowdSec snapshot" >&2
    exit 1
  fi
  if [[ ! -d "$operator_snapshot" || -L "$operator_snapshot" ]]; then
    echo "[offline-install] the supplied CrowdSec snapshot must be a directory" >&2
    exit 1
  fi
elif [[ -d "$embedded_snapshot" ]]; then
  snapshot="$embedded_snapshot"
fi
if [[ "$EASY_WAF_INSTALL_CROWDSEC" == 1 ]]; then
  if [[ "$CROWDSEC" != 1 ]]; then
    echo "[offline-install] the base bundle has no CrowdSec packages" >&2
    exit 1
  fi
  status="$(dpkg-query -W -f='${db:Status-Status}' crowdsec 2>/dev/null || true)"
  pending=/etc/crowdsec/.easy-waf-offline-install
  if [[ "$status" == installed && ! -e "$pending" && ! -L "$pending" ]]; then
    EASY_WAF_OFFLINE_CROWDSEC_PREPARED=existing
  else
    if [[ -z "$snapshot" ]]; then
      echo "[offline-install] CrowdSec requires a prepared snapshot. Set EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR or use EASY_WAF_INSTALL_CROWDSEC=0." >&2
      exit 1
    fi
    command -v python3 >/dev/null || {
      echo "[offline-install] Python 3 is required to activate the CrowdSec snapshot" >&2
      exit 1
    }
    EASY_WAF_OFFLINE_CROWDSEC_PREPARED=new
  fi
fi

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

TEMP_DIR="$(mktemp -d /tmp/easy-waf-offline.XXXXXXXXXX)"
trap 'rm -rf "$TEMP_DIR"' EXIT
chmod 0711 "$TEMP_DIR"
mkdir -m 0755 -- "${TEMP_DIR}/lists" "${TEMP_DIR}/empty"
printf 'deb [trusted=yes] %s ./\n' "$(apt_repository_uri "${SCRIPT_DIR}/repository")" >"${TEMP_DIR}/sources.list"
cat >"${TEMP_DIR}/apt.conf" <<EOF
Dir::Etc::main "/dev/null";
Dir::Etc::parts "${TEMP_DIR}/empty";
Dir::Etc::sourcelist "${TEMP_DIR}/sources.list";
Dir::Etc::sourceparts "${TEMP_DIR}/empty";
Dir::State::lists "${TEMP_DIR}/lists";
Dir::Cache::pkgcache "";
Dir::Cache::srcpkgcache "";
Acquire::Languages "none";
APT::Install-Recommends "false";
EOF

echo "[offline-install] using only the verified local repository"
export APT_CONFIG="${TEMP_DIR}/apt.conf"
unset EASY_WAF_APT_UPDATED
export EASY_WAF_OFFLINE=1
export EASY_WAF_REPO_ROOT="${SCRIPT_DIR}/payload"
export EASY_WAF_RELEASE_VERSION="$BUNDLE_VERSION"
export EASY_WAF_INSTALL_BUILD_DEPS=0
export EASY_WAF_BUILD_FROM_SOURCE=0
export EASY_WAF_INSTALL_CROWDSEC
if [[ "${EASY_WAF_OFFLINE_CROWDSEC_PREPARED:-}" == new ]]; then
  python3 -I "$SCRIPT_DIR/payload/scripts/lib/install-offline-crowdsec.py" "$snapshot" "$SCRIPT_DIR/repository"
fi
if [[ -v EASY_WAF_OFFLINE_CROWDSEC_PREPARED ]]; then
  export EASY_WAF_OFFLINE_CROWDSEC_PREPARED
fi
bash "${SCRIPT_DIR}/payload/scripts/install.sh"
