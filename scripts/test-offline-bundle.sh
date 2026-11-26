#!/usr/bin/env bash
# Smoke-test offline bundle integrity verification without root or host changes.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

probe="$TEMP_DIR/probe"
mkdir -p "$probe/payload/dist" "$probe/repository"
cp "${SCRIPT_DIR}/install-offline-bundle.sh" "$probe/install.sh"
write_fixture_metadata() {
  local directory="$1" version="$2" arch="$3"
  printf 'EASY_WAF_BUNDLE_VERSION=%s\nEASY_WAF_BUNDLE_UBUNTU=24.04\nEASY_WAF_BUNDLE_ARCH=%s\nEASY_WAF_BUNDLE_CROWDSEC=0\n' \
    "$version" "$arch" >"$directory/BUNDLE.env"
}
write_fixture_metadata "$probe" 9.9.9 amd64
fixture_package=easy-waf_9.9.9_amd64.deb
printf 'fixture package\n' >"$probe/payload/dist/$fixture_package"
cp "$probe/payload/dist/$fixture_package" "$probe/repository/$fixture_package"
(cd "$probe/payload/dist" && sha256sum "$fixture_package" >SHA256SUMS)
printf 'test payload\n' >"$probe/payload.txt"
(
  cd "$probe"
  find . -type f ! -path './SHA256SUMS' -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum -- >SHA256SUMS
)

"${BASH}" "$probe/install.sh" --verify-only >/dev/null
original_sums="$TEMP_DIR/original-sums"
cp "$probe/SHA256SUMS" "$original_sums"
reject_verification() {
  local description="$1"
  if "${BASH}" "$probe/install.sh" --verify-only >/dev/null 2>&1; then
    echo "test-offline-bundle: accepted $description" >&2
    exit 1
  fi
}
(
  cd "$probe"
  sha256sum ./install.sh >SHA256SUMS
)
reject_verification 'a checksum manifest omitting a file'
cp "$original_sums" "$probe/SHA256SUMS"
printf 'extra file\n' >"$probe/unlisted.txt"
reject_verification 'an unlisted file'
rm -- "$probe/unlisted.txt"
if ln -s missing "$probe/unlisted-link" 2>/dev/null && [[ -L "$probe/unlisted-link" ]]; then
  reject_verification 'an unlisted dangling symlink'
fi
rm -f -- "$probe/unlisted-link"
printf 'malformed checksum record\n' >>"$probe/SHA256SUMS"
if "${BASH}" "$probe/install.sh" --verify-only >"$TEMP_DIR/verify-error" 2>&1; then
  echo "test-offline-bundle: accepted a malformed outer checksum manifest" >&2
  exit 1
fi
grep -Fq 'bundle verification failed' "$TEMP_DIR/verify-error"
mv "$original_sums" "$probe/SHA256SUMS"

printf 'tampered\n' >>"$probe/payload.txt"
if "${BASH}" "$probe/install.sh" --verify-only >/dev/null 2>&1; then
  echo "test-offline-bundle: tampered bundle was accepted" >&2
  exit 1
fi

# shellcheck source=lib/offline-apt.sh
. "$SCRIPT_DIR/lib/offline-apt.sh"
[[ "$(apt_repository_uri '/tmp/large disk #1%/repository')" == 'file:/tmp/large%20disk%20%231%25/repository' ]]
[[ "$(apt_repository_uri '/tmp/архив/repository')" == 'file:/tmp/%D0%B0%D1%80%D1%85%D0%B8%D0%B2/repository' ]]

# The offline builder and installer must accept the same prerelease DEB as
# the release workflow. A bare tilde in a Bash substitution can expand.
(
  fixture_version='1.7.0~rc.1'
  dpkg-deb() {
    case "$*" in
      '-f fixture.deb Package') printf '%s\n' easy-waf ;;
      '-f fixture.deb Architecture') printf '%s\n' arm64 ;;
      '-f fixture.deb Version') printf '%s\n' "$fixture_version" ;;
      *) return 90 ;;
    esac
  }
  dpkg() {
    [[ "$*" == '--compare-versions 1.7.0~rc.1 eq 1.7.0~rc.1' ]]
  }
  offline_check_package_identity fixture.deb 1.7.0-rc.1 arm64
  fixture_version='1.7.0~rc.2'
  if offline_check_package_identity fixture.deb 1.7.0-rc.1 arm64 2>"$TEMP_DIR/identity-error"; then
    echo "test-offline-bundle: accepted the wrong prerelease" >&2
    exit 1
  fi
  grep -Fq 'expected easy-waf 1.7.0~rc.1 (arm64)' "$TEMP_DIR/identity-error"
)

# Exercise the actual builder step without relying on a platform's dpkg.
(
  manifest_step="$(sed -n '/^write_package_manifest() {$/,/^}$/p' "$SCRIPT_DIR/build-offline-bundle.sh")"
  [[ -n "$manifest_step" ]]
  eval "$manifest_step"
  repository="$TEMP_DIR/metadata fixture"
  mkdir "$repository"
  touch "$repository/one.deb"
  mode=ok
  # Called by the builder function loaded through eval.
  # shellcheck disable=SC2329,SC2317
  dpkg-deb() {
    [[ "$*" == "-f $repository/one.deb Package Version Architecture Source" ]] || return 90
    printf 'Package: fixture\nArchitecture: arm64\n'
    [[ "$mode" == missing_version ]] || printf 'Version: 2:1.0-1\n'
    [[ "$mode" != with_source ]] || printf 'Source: fixture-source (2:1.0-1)\n'
    [[ "$mode" != read_failure ]]
  }
  for mode in ok with_source; do
    source_field=''
    [[ "$mode" != with_source ]] || source_field='fixture-source (2:1.0-1)'
    printf 'package\tversion\tarchitecture\tsource\nfixture\t2:1.0-1\tarm64\t%s\n' "$source_field" >"$TEMP_DIR/expected.tsv"
    write_package_manifest "$repository" >"$TEMP_DIR/actual.tsv"
    cmp "$TEMP_DIR/expected.tsv" "$TEMP_DIR/actual.tsv"
  done
  for mode in missing_version read_failure; do
    if write_package_manifest "$repository" >"$TEMP_DIR/actual.tsv" 2>"$TEMP_DIR/metadata-error"; then
      echo "test-offline-bundle: accepted invalid package metadata ($mode)" >&2
      exit 1
    fi
    grep -Fq 'could not read package metadata: one.deb' "$TEMP_DIR/metadata-error"
  done
)

# A failed writer must leave an older image and archive in place, even
# when the other requested format was already written successfully.
(
  output_step="$(sed -n '/^write_bundle_outputs() ($/,/^)/p' "$SCRIPT_DIR/build-offline-bundle.sh")"
  [[ -n "$output_step" ]]
  eval "$output_step"
  OUTPUT_DIR="$TEMP_DIR/output #1%"
  STAGE="$TEMP_DIR/input"
  VERSION=9.9.9
  ARCH=amd64
  BASE="easy-waf_${VERSION}_offline_ubuntu24.04_${ARCH}"
  export FORMAT=both
  mkdir -p "$OUTPUT_DIR" "$STAGE"
  printf 'checkout fixture\n' >"$STAGE/input.txt"
  printf 'old ISO\n' >"$OUTPUT_DIR/$BASE.iso"
  printf 'old archive\n' >"$OUTPUT_DIR/$BASE.tar.gz"

  # Invoked by the builder function loaded through eval.
  # shellcheck disable=SC2317,SC2329
  xorriso() {
    while [[ "$1" != -o ]]; do shift; done
    printf 'candidate ISO\n' >"$2"
    [[ "$failure" != iso ]]
  }
  # shellcheck disable=SC2317,SC2329
  tar() {
    printf 'candidate archive\n' >"$2"
    [[ "$failure" != archive ]]
  }
  for failure in iso archive; do
    if write_bundle_outputs; then
      echo "test-offline-bundle: build accepted a failed $failure writer" >&2
      exit 1
    fi
    [[ "$(<"$OUTPUT_DIR/$BASE.iso")" == 'old ISO' ]]
    [[ "$(<"$OUTPUT_DIR/$BASE.tar.gz")" == 'old archive' ]]
    [[ -z "$(find "$OUTPUT_DIR" -mindepth 1 -type d -print -quit)" ]]
  done
  failure=none
  write_bundle_outputs
  [[ "$(<"$OUTPUT_DIR/$BASE.iso")" == 'candidate ISO' ]]
  [[ "$(<"$OUTPUT_DIR/$BASE.tar.gz")" == 'candidate archive' ]]
  [[ -z "$(find "$OUTPUT_DIR" -mindepth 1 -type d -print -quit)" ]]
)

# Use the actual builder's checksum step. The nested manifest must be verified
# by the outer one, and the outer manifest cannot list a temporary self-entry.
STAGE="${TEMP_DIR}/stage #1%"
PAYLOAD="${STAGE}/payload"
WORK_DIR="${TEMP_DIR}/outside"
mkdir -p "$PAYLOAD/dist" "$WORK_DIR" "$STAGE/repository"
VERSION=9.9.9
ARCH=amd64
write_fixture_metadata "$STAGE" "$VERSION" "$ARCH"
printf 'payload\n' >"${STAGE}/payload.txt"
printf 'fixture package\n' >"$PAYLOAD/dist/easy-waf_${VERSION}_${ARCH}.deb"
cp "$PAYLOAD/dist/easy-waf_${VERSION}_${ARCH}.deb" "$STAGE/repository/"
cp "${SCRIPT_DIR}/install-offline-bundle.sh" "${STAGE}/install.sh"
checksum_step="$(sed -n '/^write_bundle_checksums() {$/,/^}$/p' "$SCRIPT_DIR/build-offline-bundle.sh")"
[[ -n "$checksum_step" ]] || { echo 'test-offline-bundle: builder checksum step missing' >&2; exit 1; }
eval "$checksum_step"
write_bundle_checksums
(cd "$PAYLOAD/dist" && sha256sum -c --quiet SHA256SUMS)
grep -Eq ' [ *]\./payload/dist/SHA256SUMS$' "${STAGE}/SHA256SUMS"
if grep -q 'SHA256SUMS\.tmp' "${STAGE}/SHA256SUMS"; then
  echo "test-offline-bundle: checksum list includes SHA256SUMS.tmp" >&2
  exit 1
fi
"${BASH}" "${STAGE}/install.sh" --verify-only >/dev/null
printf '\n' >>"$PAYLOAD/dist/SHA256SUMS"
if "${BASH}" "${STAGE}/install.sh" --verify-only >/dev/null 2>&1; then
  echo 'test-offline-bundle: modified package manifest was accepted' >&2
  exit 1
fi

# CI compares the extracted ISO to the separately verified release package.
release_name="easy-waf_${VERSION}_${ARCH}.deb"
release_fixture="$TEMP_DIR/$release_name"
cp "$PAYLOAD/dist/$release_name" "$release_fixture"
mkdir -p "$STAGE/repository"
cp "$release_fixture" "$STAGE/repository/$release_name"
verify_release="$SCRIPT_DIR/verify-offline-release-package.sh"
write_bundle_checksums
"${BASH}" "$verify_release" "$STAGE" "$release_fixture"
for location in payload/dist repository; do
  copy="$STAGE/$location/$release_name"
  printf 'different package\n' >"$copy"
  write_bundle_checksums
  if "${BASH}" "$STAGE/install.sh" --verify-only >"$TEMP_DIR/verify-error" 2>&1; then
    echo "test-offline-bundle: verify-only accepted disagreeing package copies" >&2
    exit 1
  fi
  grep -Fq "repository/$release_name does not match the verified installer payload" "$TEMP_DIR/verify-error"
  if "${BASH}" "$verify_release" "$STAGE" "$release_fixture" >"$TEMP_DIR/release-error" 2>&1; then
    echo "test-offline-bundle: accepted a package differing from the release in $location" >&2
    exit 1
  fi
  grep -Fq "$location/$release_name does not match" "$TEMP_DIR/release-error"
  cp "$release_fixture" "$copy"
done
printf 'unusable checksum list\n' >"$PAYLOAD/dist/SHA256SUMS"
(cd "$STAGE" && find . -type f ! -path './SHA256SUMS' -print0 |
  LC_ALL=C sort -z | xargs -0 -r sha256sum -- >SHA256SUMS)
if "${BASH}" "$STAGE/install.sh" --verify-only >"$TEMP_DIR/verify-error" 2>&1; then
  echo "test-offline-bundle: verify-only accepted an unusable payload checksum manifest" >&2
  exit 1
fi
grep -Fq 'payload checksum manifest does not match' "$TEMP_DIR/verify-error"
if "${BASH}" "$verify_release" "$STAGE" "$release_fixture" >"$TEMP_DIR/release-error" 2>&1; then
  echo 'test-offline-bundle: accepted an unusable payload checksum manifest' >&2
  exit 1
fi
grep -Fq 'payload checksum manifest does not match' "$TEMP_DIR/release-error"
rm -- "$STAGE/repository/$release_name"

# The installer sources /etc/os-release before handing the package version
# to its payload. Exercise that handoff on its supported Ubuntu host.
if [[ "$EUID" == 0 ]] && (
  [[ -f /etc/os-release ]] || exit 1
  # shellcheck source=/dev/null
  . /etc/os-release
  [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" =~ ^(24|26)\.04$ ]]
); then
  # The release job supplies dist/<name>.deb. Exercise the builder up to the
  # APT boundary with a local DEB and without contacting package repositories.
  builder="$TEMP_DIR/relative package/build"
  mkdir -p "$builder/dist" "$builder/scripts/lib"
  install -d -m 0755 "$builder/fixture/DEBIAN"
  cp "$SCRIPT_DIR/build-offline-bundle.sh" "$builder/scripts/"
  cp "$SCRIPT_DIR/lib/offline-apt.sh" "$builder/scripts/lib/"
  printf '9.9.9\n' >"$builder/VERSION"
  ARCH="$(dpkg --print-architecture)"
  package="dist/easy-waf_9.9.9_${ARCH}.deb"
  printf 'Package: easy-waf\nVersion: 9.9.9\nArchitecture: %s\nMaintainer: Fixture <fixture@example.invalid>\nDescription: Offline bundle fixture\n' \
    "$ARCH" >"$builder/fixture/DEBIAN/control"
  dpkg-deb --build "$builder/fixture" "$builder/$package" >/dev/null
  cat >"$TEMP_DIR/apt-path-fixture.env" <<'FIXTURE'
git() { :; }
apt-ftparchive() { return 91; }
dpkg-scanpackages() { return 91; }
if [[ -n "${FIXTURE_NATIVE_ARCH:-}" ]]; then
  dpkg() { [[ "$1" == --print-architecture ]] && echo "$FIXTURE_NATIVE_ARCH"; }
fi
runuser() {
  [[ "${EXPECT_APT_TMPDIR_REUSE:-0}" == 1 && "${*: -1}" == "$TMPDIR" ]]
}
apt-get() {
  local arg archives= haproxy_args=()
  for arg in "$@"; do
    case "$arg" in
      Dir::Cache::archives=*) archives="${arg#*=}" ;;
      haproxy|haproxy=*) haproxy_args+=("$arg") ;;
    esac
  done
  local expected_haproxy=haproxy
  if [[ "$VERSION_ID" == 26.04 ]]; then expected_haproxy='haproxy=3.4.*'; fi
  [[ "${haproxy_args[*]}" == "$expected_haproxy" ]] || {
    echo "Expected APT to resolve $expected_haproxy for Ubuntu $VERSION_ID" >&2
    return 96
  }
  while [[ $# -gt 1 && "$1" != install ]]; do shift; done
  [[ "$1" == install && "$2" == /* ]] && cmp -s "$2" "$PWD/$EASY_WAF_DEB" || return 92
  [[ "${2##*/}" == "easy-waf_${VERSION}_${ARCH}.deb" ]] || return 97
  local apt_work="${archives%/resolve/cache/archives}"
  if [[ "${EXPECT_APT_TMPDIR_REUSE:-0}" == 1 ]]; then
    [[ "$apt_work" == "$TMPDIR"/easy-waf-apt.* ]] || return 94
  else
    [[ "$apt_work" == /tmp/easy-waf-apt.* ]] || return 94
  fi
  [[ "$(stat -c %a "$apt_work")" == 711 &&
     "$(stat -c %a "$archives")" == 755 &&
     "$(stat -c %a "$2")" == 644 ]] || return 95
  echo 'APT received the absolute DEB path'
  return 93
}
FIXTURE
  if FIXTURE_NATIVE_ARCH=riscv64 BASH_ENV="$TEMP_DIR/apt-path-fixture.env" EASY_WAF_OFFLINE_FORMAT=tar.gz \
    "${BASH}" "$builder/scripts/build-offline-bundle.sh" >"$TEMP_DIR/arch-error" 2>&1; then
    echo 'test-offline-bundle: builder accepted unsupported native architecture' >&2
    exit 1
  fi
  grep -Fq 'unsupported bundle architecture: riscv64' "$TEMP_DIR/arch-error"
  cp "$builder/$package" "$builder/dist/renamed candidate.deb"
  for reuse_tmpdir in 0 1; do
    input_deb="$package"
    if [[ "$reuse_tmpdir" == 1 ]]; then input_deb='dist/renamed candidate.deb'; fi
    builder_status=0
    (cd "$builder" && umask 077 && TMPDIR="$builder" EXPECT_APT_TMPDIR_REUSE="$reuse_tmpdir" \
      BASH_ENV="$TEMP_DIR/apt-path-fixture.env" EASY_WAF_DEB="$input_deb" \
      EASY_WAF_OFFLINE_FORMAT=tar.gz "${BASH}" scripts/build-offline-bundle.sh) \
      >"$TEMP_DIR/apt-path.log" 2>&1 || builder_status=$?
    if [[ "$builder_status" != 93 ]]; then
      cat "$TEMP_DIR/apt-path.log" >&2
      echo "test-offline-bundle: unexpected APT workspace (reuse TMPDIR=$reuse_tmpdir, exit=$builder_status)" >&2
      exit 1
    fi
    grep -Fxq 'APT received the absolute DEB path' "$TEMP_DIR/apt-path.log"
  done

  mkdir -p "$STAGE/repository" "$PAYLOAD/scripts/lib"
  cp "$SCRIPT_DIR/lib/offline-apt.sh" "$PAYLOAD/scripts/lib/"
  (
    cd "$STAGE/repository"
    deb="${package##*/}"
    cp "$builder/$package" "$deb"
    dpkg-deb -f "$deb" >Packages
    read -r digest _ < <(sha256sum "$deb")
    printf 'Filename: ./%s\nSize: %s\nSHA256: %s\n' "$deb" "$(stat -c %s "$deb")" "$digest" >>Packages
    # An offline VM clock may predate the checksum-verified ISO.
    read -r index_digest _ < <(sha256sum Packages)
    printf 'Date: %s\nSHA256:\n %s %s Packages\n' \
      "$(LC_ALL=C date -Ru -d '+1 day')" "$index_digest" "$(stat -c %s Packages)" >Release
  )
  # shellcheck source=/dev/null
  host_baseline="$(. /etc/os-release && printf '%s' "$VERSION_ID")"
  printf 'EASY_WAF_BUNDLE_VERSION=%s\nEASY_WAF_BUNDLE_UBUNTU=%s\nEASY_WAF_BUNDLE_ARCH=%s\nEASY_WAF_BUNDLE_CROWDSEC=0\n' \
    "$VERSION" "$host_baseline" "$(dpkg --print-architecture)" >"$STAGE/BUNDLE.env"
  cat >"$PAYLOAD/scripts/install.sh" <<'PAYLOAD'
set -eu
[[ "$EASY_WAF_RELEASE_VERSION" == 9.9.9 && "$EASY_WAF_OFFLINE" == 1 ]]
[[ "$EASY_WAF_INSTALL_CROWDSEC" == "${EXPECTED_CROWDSEC:-0}" ]]
[[ "${EASY_WAF_OFFLINE_CROWDSEC_PREPARED:-}" == "${EXPECTED_AGENT:-}" ]]
[[ ! -v EASY_WAF_APT_UPDATED ]]
for setting in EASY_WAF_DIST_DIR EASY_WAF_INSTALL_FROM_PACKAGE EASY_WAF_SKIP_BINARY_FETCH; do
  if [[ -v "$setting" ]]; then
    printf 'offline payload inherited package selection setting %s\n' "$setting" >&2
    exit 1
  fi
done
if [[ "${CHECK_APT_REPOSITORY:-0}" == 1 ]]; then
  apt_dir="${APT_CONFIG%/*}"
  printf '%s\n' "$apt_dir" >"$APT_WORKSPACE"
  grep -Fq '/stage%20%231%25/repository ./' "$apt_dir/sources.list"
  apt-config dump >"$apt_dir/effective.conf"
  grep -Fxq "Dir::State::lists \"$apt_dir/lists\";" "$apt_dir/effective.conf"
  grep -Fxq 'Dir::Etc::main "/dev/null";' "$apt_dir/effective.conf"
  grep -Fxq "Dir::Etc::parts \"$apt_dir/empty\";" "$apt_dir/effective.conf"
  grep -Fxq "Dir::Etc::sourceparts \"$apt_dir/empty\";" "$apt_dir/effective.conf"
  [[ -z "$(ls -A "$apt_dir/lists")" && "$(stat -c %a "$apt_dir")" == 711 ]]
  : >"$apt_dir/status"
  # Keep the fixture independent of the host dpkg database and container caps.
  apt_fixture=(-o "Dir::State::status=$apt_dir/status" -o APT::Sandbox::User=root)
  apt-get "${apt_fixture[@]}" -qq update
  (cd "$apt_dir" && apt-get "${apt_fixture[@]}" -qq download easy-waf)
  deb="easy-waf_9.9.9_$(dpkg --print-architecture).deb"
  cmp "repository/$deb" "$apt_dir/$deb"
fi
PAYLOAD
  cat >"$TEMP_DIR/handoff-fixture.env" <<'FIXTURE'
mkdir() {
  if [[ "$*" == '-p /var/cache/apt/archives/partial' ]]; then
    : >"$HOST_CHANGES"
    return 0
  fi
  command mkdir "$@"
}
df() {
  printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture 8388608 0 8388608 0%% /\n'
}
dpkg-query() {
  printf '%s' "${FIXTURE_AGENT_STATUS:-not-installed}"
}
python3() {
  [[ "$1" == -I && "$2" == */scripts/lib/install-offline-crowdsec.py ]] || return 91
  printf '%s\n' "$3" >"$SNAPSHOT_ARGUMENT"
}
FIXTURE
  export HOST_CHANGES="$TEMP_DIR/host-changes" SNAPSHOT_ARGUMENT="$TEMP_DIR/snapshot-argument"
  export APT_WORKSPACE="$TEMP_DIR/apt-workspace"
  export BASH_ENV="$TEMP_DIR/handoff-fixture.env"
  other_baseline=26.04
  cp "$builder/$package" "$PAYLOAD/$package"
  [[ "$host_baseline" == 24.04 ]] || other_baseline=24.04
  sed -i "s/^EASY_WAF_BUNDLE_UBUNTU=.*/EASY_WAF_BUNDLE_UBUNTU=$other_baseline/" "$STAGE/BUNDLE.env"
  write_bundle_checksums
  if "${BASH}" "$STAGE/install.sh" >"$TEMP_DIR/error" 2>&1; then
    echo 'test-offline-bundle: accepted a bundle for a different Ubuntu release' >&2
    exit 1
  fi
  grep -Fq "requires Ubuntu $other_baseline; found ubuntu $host_baseline" "$TEMP_DIR/error"
  [[ ! -e "$HOST_CHANGES" && ! -e "$APT_WORKSPACE" ]]
  sed -i "s/^EASY_WAF_BUNDLE_UBUNTU=.*/EASY_WAF_BUNDLE_UBUNTU=$host_baseline/" "$STAGE/BUNDLE.env"
  install -d -m 0755 "$builder/wrong/DEBIAN"
  sed 's/^Version: 9\.9\.9$/Version: 9.9.8/' "$builder/fixture/DEBIAN/control" >"$builder/wrong/DEBIAN/control"
  dpkg-deb --build "$builder/wrong" "$PAYLOAD/$package" >/dev/null
  # Keep both copies identical so the installer reaches the DEB version check.
  cp "$PAYLOAD/$package" "$STAGE/repository/${package##*/}"
  write_bundle_checksums
  if "${BASH}" "$STAGE/install.sh" >"$TEMP_DIR/error" 2>&1; then
    echo 'test-offline-bundle: installed a package with the wrong declared version' >&2
    exit 1
  fi
  grep -Fq 'expected easy-waf 9.9.9' "$TEMP_DIR/error"
  [[ ! -e "$HOST_CHANGES" && ! -e "$APT_WORKSPACE" ]]

  cp "$builder/$package" "$PAYLOAD/$package"
  # A different build can have the same Debian name, version and architecture.
  # Even a consistent outer checksum manifest must not authorize that mismatch.
  printf 'different package contents\n' >"$builder/fixture/build-id"
  dpkg-deb --build "$builder/fixture" "$STAGE/repository/${package##*/}" >/dev/null
  write_bundle_checksums
  if "${BASH}" "$STAGE/install.sh" >"$TEMP_DIR/error" 2>&1; then
    echo 'test-offline-bundle: installer accepted mismatched repository package bytes' >&2
    exit 1
  fi
  grep -Fq "repository/${package##*/} does not match the verified installer payload" "$TEMP_DIR/error"
  [[ ! -e "$HOST_CHANGES" && ! -e "$APT_WORKSPACE" ]]

  cp "$builder/$package" "$STAGE/repository/${package##*/}"
  write_bundle_checksums
  mkdir "$TEMP_DIR/local binaries"
  printf 'outside bundle\n' >"$TEMP_DIR/local binaries/easy-waf-api"
  if ! EASY_WAF_APT_UPDATED=1 EASY_WAF_INSTALL_FROM_PACKAGE=0 EASY_WAF_SKIP_BINARY_FETCH=1 \
    EASY_WAF_DIST_DIR="$TEMP_DIR/local binaries" CHECK_APT_REPOSITORY=1 "${BASH}" "$STAGE/install.sh" >/dev/null; then
    echo 'test-offline-bundle: installer could not use the local APT repository' >&2
    exit 1
  fi
  [[ ! -e "$(< "$APT_WORKSPACE")" ]]
  rm -- "$HOST_CHANGES"
  if EASY_WAF_INSTALL_CROWDSEC=1 "${BASH}" "$STAGE/install.sh" >"$TEMP_DIR/error" 2>&1; then
    echo 'test-offline-bundle: base bundle accepted CrowdSec provisioning' >&2
    exit 1
  fi
  grep -Fq 'base bundle has no CrowdSec packages' "$TEMP_DIR/error"
  [[ ! -e "$HOST_CHANGES" ]]

  sed -i 's/EASY_WAF_BUNDLE_CROWDSEC=0/EASY_WAF_BUNDLE_CROWDSEC=1/' "$STAGE/BUNDLE.env"
  write_bundle_checksums
  if "${BASH}" "$STAGE/install.sh" >"$TEMP_DIR/error" 2>&1; then
    echo 'test-offline-bundle: full bundle accepted a fresh install without a snapshot' >&2
    exit 1
  fi
  grep -Fq 'CrowdSec requires a prepared snapshot' "$TEMP_DIR/error"
  [[ ! -e "$HOST_CHANGES" ]]
  EASY_WAF_INSTALL_CROWDSEC=0 "${BASH}" "$STAGE/install.sh" >/dev/null
  EXPECTED_CROWDSEC=1 EXPECTED_AGENT=existing FIXTURE_AGENT_STATUS=installed "${BASH}" "$STAGE/install.sh" >/dev/null
  [[ ! -e "$SNAPSHOT_ARGUMENT" ]]

  mkdir -p "$TEMP_DIR/operator snapshot"
  (
    cd "$TEMP_DIR"
    EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR='operator snapshot' EXPECTED_CROWDSEC=1 EXPECTED_AGENT=new \
      "${BASH}" "$STAGE/install.sh" >/dev/null
  )
  [[ "$(cat "$SNAPSHOT_ARGUMENT")" == "$TEMP_DIR/operator snapshot" ]]
  mkdir -p "$PAYLOAD/crowdsec-snapshot"
  write_bundle_checksums
  EXPECTED_CROWDSEC=1 EXPECTED_AGENT=new "${BASH}" "$STAGE/install.sh" >/dev/null
  [[ "$(cat "$SNAPSHOT_ARGUMENT")" == "$PAYLOAD/crowdsec-snapshot" ]]
  if EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR="$TEMP_DIR/operator snapshot" "${BASH}" "$STAGE/install.sh" >"$TEMP_DIR/error" 2>&1; then
    echo 'test-offline-bundle: operator snapshot was accepted for a private bundle' >&2
    exit 1
  fi
  grep -Fq 'already has an embedded CrowdSec snapshot' "$TEMP_DIR/error"
  unset BASH_ENV HOST_CHANGES SNAPSHOT_ARGUMENT
fi

# Exercise the connected snapshot preparer with a CLI fixture and no downloads.
cat >"$TEMP_DIR/cscli fixture" <<'CLI'
#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  version) echo 'version: v1.8.2-fixture' ;;
  '-c cscli.yaml hub branch') echo master ;;
  '-c cscli.yaml hub update --with-content')
    grep -q 'hub_branch: "master"' cscli.yaml
    printf '{}\n' >snapshot/hub/.index.json
    ;;
  '-c cscli.yaml setup install-hub snapshot/setup.yaml --color no')
    grep -q 'crowdsecurity/haproxy' snapshot/setup.yaml
    grep -q 'crowdsecurity/pgsql' snapshot/setup.yaml
    printf 'fixture parser\n' >snapshot/hub/parser.yaml
    printf 'fixture data\n' >snapshot/data/fixture.txt
    printf 'working config\n' >working/private.yaml
    [[ "${CSCLI_FIXTURE_FAIL:-0}" != 1 ]]
    ;;
  *) exit 2 ;;
esac
CLI
chmod +x "$TEMP_DIR/cscli fixture"
preparer="$SCRIPT_DIR/prepare-offline-crowdsec.sh"
output="$TEMP_DIR/local snapshot"
CSCLI="$TEMP_DIR/cscli fixture" "${BASH}" "$preparer" "$output" >/dev/null
(
  cd "$output"
  sha256sum -c SHA256SUMS >/dev/null
  grep -q '^CROWDSEC_CLI_VERSION=v1.8.2-fixture$' SNAPSHOT.env
  [[ -f hub/.index.json && -f hub/parser.yaml && -f data/fixture.txt && ! -e working ]]
)
if CSCLI="$TEMP_DIR/cscli fixture" "${BASH}" "$preparer" "$output" >/dev/null 2>&1; then
  echo 'test-offline-bundle: existing snapshot was accepted as output' >&2
  exit 1
fi
if CSCLI_FIXTURE_FAIL=1 CSCLI="$TEMP_DIR/cscli fixture" "${BASH}" "$preparer" "$TEMP_DIR/failed" >/dev/null 2>&1; then
  echo 'test-offline-bundle: a failed snapshot preparation returned success' >&2
  exit 1
fi
[[ ! -e "$TEMP_DIR/failed" ]]
[[ -z "$(find "$TEMP_DIR" -maxdepth 1 -name '.crowdsec-snapshot.*' -print -quit)" ]]

if command -v python3 >/dev/null; then
  python3 -B -I "$SCRIPT_DIR/test-offline-crowdsec-snapshot.py"
  python3 -B -I "$SCRIPT_DIR/test-install-offline-crowdsec.py"
fi
echo "test-offline-bundle: PASS"
