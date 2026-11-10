#!/usr/bin/env bash
# Build a self-contained Easy Home WAF APT repository and offline ISO.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: bash scripts/build-offline-bundle.sh

Builds a versioned offline ISO for the native architecture. Run on Ubuntu 24.04
with the Ubuntu repositories and, for the default full profile, the pinned
CrowdSec repository already configured.

Environment:
  EASY_WAF_DEB=/path/easy-waf_<version>_<arch>.deb
  EASY_WAF_OFFLINE_OUTPUT_DIR=dist
  EASY_WAF_OFFLINE_INCLUDE_CROWDSEC=1|0  (default: 1)
  EASY_WAF_OFFLINE_FORMAT=iso|tar.gz|both (default: iso)
EOF
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi

for command_name in apt-get apt-ftparchive dpkg dpkg-deb dpkg-scanpackages git sha256sum tar; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "[offline-build] missing command: $command_name" >&2
    exit 1
  }
done

# shellcheck source=/dev/null
. /etc/os-release
if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "24.04" ]]; then
  echo "[offline-build] Ubuntu 24.04 is required; found ${ID:-unknown} ${VERSION_ID:-unknown}" >&2
  exit 1
fi

VERSION="$(head -1 "${REPO_ROOT}/VERSION" | tr -d '[:space:]')"
ARCH="$(dpkg --print-architecture)"
OUTPUT_DIR="${EASY_WAF_OFFLINE_OUTPUT_DIR:-${REPO_ROOT}/dist}"
INCLUDE_CROWDSEC="${EASY_WAF_OFFLINE_INCLUDE_CROWDSEC:-1}"
FORMAT="${EASY_WAF_OFFLINE_FORMAT:-iso}"
DEB="${EASY_WAF_DEB:-${REPO_ROOT}/dist/easy-waf_${VERSION}_${ARCH}.deb}"

case "$FORMAT" in
  iso)
    command -v xorriso >/dev/null 2>&1 || {
      echo "[offline-build] xorriso is required for EASY_WAF_OFFLINE_FORMAT=iso" >&2
      exit 1
    }
    ;;
  tar.gz) ;;
  both)
    command -v xorriso >/dev/null 2>&1 || {
      echo "[offline-build] xorriso is required for EASY_WAF_OFFLINE_FORMAT=both" >&2
      exit 1
    }
    ;;
  *)
    echo "[offline-build] unsupported format: $FORMAT" >&2
    exit 2
    ;;
esac

[[ -f "$DEB" ]] || {
  echo "[offline-build] Easy WAF package not found: $DEB" >&2
  exit 1
}
DEB_ARCH="$(dpkg-deb -f "$DEB" Architecture)"
if [[ "$DEB_ARCH" != "$ARCH" ]]; then
  echo "[offline-build] package architecture $DEB_ARCH does not match native $ARCH" >&2
  exit 1
fi
DEB_PACKAGE="$(dpkg-deb -f "$DEB" Package)"
DEB_VERSION="$(dpkg-deb -f "$DEB" Version)"
EXPECTED_DEB_VERSION="${VERSION//-/~}"
if [[ "$DEB_PACKAGE" != "easy-waf" ]] || ! dpkg --compare-versions "$DEB_VERSION" eq "$EXPECTED_DEB_VERSION"; then
  echo "[offline-build] expected easy-waf $EXPECTED_DEB_VERSION; package contains $DEB_PACKAGE $DEB_VERSION" >&2
  exit 1
fi

# Release payloads come only from committed files. This prevents an ignored or
# untracked credential below scripts/configs from being copied into an ISO.
tracked_inputs=(scripts configs/defaults packaging/systemd packaging/polkit VERSION LICENSE NOTICE)
if ! git -C "$REPO_ROOT" diff --quiet -- "${tracked_inputs[@]}" ||
  ! git -C "$REPO_ROOT" diff --cached --quiet -- "${tracked_inputs[@]}" ||
  [[ -n "$(git -C "$REPO_ROOT" ls-files --others --exclude-standard -- "${tracked_inputs[@]}")" ]]; then
  echo "[offline-build] bundle inputs must be committed and clean" >&2
  exit 1
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
STAGE="${WORK_DIR}/easy-waf-offline"
APT_REPO="${STAGE}/repository"
PAYLOAD="${STAGE}/payload"
mkdir -p "$APT_REPO" "$PAYLOAD/dist" "$OUTPUT_DIR"

packages=(
  haproxy nftables ca-certificates curl iproute2 netplan.io iputils-ping
  traceroute iputils-tracepath systemd policykit-1 sudo fail2ban
  postgresql postgresql-contrib adduser polkitd
)
if [[ "$INCLUDE_CROWDSEC" == "1" ]]; then
  packages+=(crowdsec crowdsec-haproxy-spoa-bouncer)
elif [[ "$INCLUDE_CROWDSEC" != "0" ]]; then
  echo "[offline-build] EASY_WAF_OFFLINE_INCLUDE_CROWDSEC must be 0 or 1" >&2
  exit 2
fi

echo "[offline-build] resolving ${#packages[@]} roots for Ubuntu 24.04/$ARCH"
# Download the concrete closure APT would install on an empty system.
# apt-rdepends also prints virtual names (dbus-system-bus, libgnutls30,
# systemd-sysusers, ...). Those have no candidate, so apt-get download fails
# before the repository exists. The solver below picks one real provider
# (dbus rather than dbus-broker, debconf rather than cdebconf).
RESOLVE="${WORK_DIR}/resolve"
mkdir -p "${RESOLVE}/cache/archives/partial"
: >"${RESOLVE}/status"
apt_resolve_opts=(
  -o "Dir::State::status=${RESOLVE}/status"
  -o "Dir::State::lists=/var/lib/apt/lists"
  -o "Dir::Cache=${RESOLVE}/cache"
  -o "Dir::Cache::archives=${RESOLVE}/cache/archives"
  -o "Dir::Etc::sourcelist=/etc/apt/sources.list"
  -o "Dir::Etc::sourceparts=/etc/apt/sources.list.d"
  -o "Debug::NoLocking=true"
  -o "APT::Install-Recommends=false"
  -o "APT::Install-Suggests=false"
  -o "APT::Get::Assume-Yes=true"
  -o "Acquire::Languages=none"
)
apt-get "${apt_resolve_opts[@]}" --download-only install "${packages[@]}"
find "${RESOLVE}/cache/archives" -maxdepth 1 -type f -name '*.deb' -exec mv -t "$APT_REPO" {} +
mapfile -d '' downloaded_debs < <(find "$APT_REPO" -maxdepth 1 -type f -name '*.deb' -print0)
if [[ "${#downloaded_debs[@]}" -lt 1 ]]; then
  echo "[offline-build] APT downloaded no packages" >&2
  exit 1
fi
echo "[offline-build] downloaded ${#downloaded_debs[@]} packages"

cp -a "$DEB" "$APT_REPO/"
cp -a "$DEB" "$PAYLOAD/dist/easy-waf_${VERSION}_${ARCH}.deb"
git -C "$REPO_ROOT" archive --format=tar HEAD -- "${tracked_inputs[@]}" | tar -xf - -C "$PAYLOAD"
cp -a "${PAYLOAD}/scripts/install-offline-bundle.sh" "${STAGE}/install.sh"
chmod 0755 "${STAGE}/install.sh"

(
  cd "$APT_REPO"
  dpkg-scanpackages --multiversion . /dev/null >Packages
  gzip -9 -c Packages >Packages.gz
  apt-ftparchive release . >Release
)

{
  printf 'package\tversion\tarchitecture\tsource\n'
  while IFS= read -r package_file; do
    printf '%s\t%s\t%s\t%s\n' \
      "$(dpkg-deb -f "$package_file" Package)" \
      "$(dpkg-deb -f "$package_file" Version)" \
      "$(dpkg-deb -f "$package_file" Architecture)" \
      "$(dpkg-deb -f "$package_file" Source 2>/dev/null || true)"
  done < <(find "$APT_REPO" -maxdepth 1 -type f -name '*.deb' | LC_ALL=C sort)
} >"${STAGE}/PACKAGE-MANIFEST.tsv"

cat >"${STAGE}/BUNDLE.env" <<EOF
EASY_WAF_BUNDLE_VERSION=${VERSION}
EASY_WAF_BUNDLE_UBUNTU=24.04
EASY_WAF_BUNDLE_ARCH=${ARCH}
EASY_WAF_BUNDLE_CROWDSEC=${INCLUDE_CROWDSEC}
EOF

cat >"${STAGE}/README.txt" <<EOF
Easy Home WAF ${VERSION} offline bundle for Ubuntu 24.04/${ARCH}

Verify the ISO checksum and Sigstore bundle on a connected trusted workstation,
transfer or mount the ISO, then on the appliance run:

  sudo bash install.sh

The installer verifies the internal SHA256SUMS before using the local APT
repository. It does not use configured online APT sources.
EOF

# Validate the repository with APT's real solver against an empty package state.
# This catches missing alternatives/providers and versioned dependencies before
# an ISO can be signed, without running maintainer scripts on the build host.
SOLVER="${WORK_DIR}/solver"
mkdir -p "${SOLVER}/lists/partial" "${SOLVER}/cache/archives/partial"
: >"${SOLVER}/status"
cat >"${SOLVER}/sources.list" <<EOF
deb [trusted=yes] file:${APT_REPO} ./
EOF
apt_opts=(
  -o "Dir::Etc::sourcelist=${SOLVER}/sources.list"
  -o "Dir::Etc::sourceparts=-"
  -o "Dir::State::status=${SOLVER}/status"
  -o "Dir::State::lists=${SOLVER}/lists"
  -o "Dir::Cache=${SOLVER}/cache"
  -o "APT::Get::List-Cleanup=0"
  -o "APT::Install-Recommends=false"
  -o "Acquire::Languages=none"
)
apt-get "${apt_opts[@]}" update -qq
apt-get "${apt_opts[@]}" --simulate install easy-waf "${packages[@]}" >/dev/null
echo "[offline-build] isolated APT dependency solve passed"

(
  cd "$STAGE"
  find . -type f ! -name SHA256SUMS -print0 |
    LC_ALL=C sort -z |
    xargs -0 sha256sum >SHA256SUMS.tmp
  mv SHA256SUMS.tmp SHA256SUMS
)

BASE="easy-waf_${VERSION}_offline_ubuntu24.04_${ARCH}"
if [[ "$FORMAT" == "iso" || "$FORMAT" == "both" ]]; then
  ISO="${OUTPUT_DIR}/${BASE}.iso"
  xorriso -as mkisofs -quiet -r -J -V "EASYWAF_${VERSION}_${ARCH}" -o "$ISO" "$STAGE"
  echo "[offline-build] built $ISO"
fi
if [[ "$FORMAT" == "tar.gz" || "$FORMAT" == "both" ]]; then
  TGZ="${OUTPUT_DIR}/${BASE}.tar.gz"
  tar -czf "$TGZ" -C "$STAGE" .
  echo "[offline-build] built $TGZ"
fi
