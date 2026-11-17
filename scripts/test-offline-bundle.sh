#!/usr/bin/env bash
# Smoke-test offline bundle integrity verification without root or host changes.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

cp "${SCRIPT_DIR}/install-offline-bundle.sh" "${TEMP_DIR}/install.sh"
printf 'test payload\n' >"${TEMP_DIR}/payload.txt"
(
  cd "$TEMP_DIR"
  sha256sum install.sh payload.txt >SHA256SUMS
)

"${BASH}" "${TEMP_DIR}/install.sh" --verify-only >/dev/null
printf 'tampered\n' >>"${TEMP_DIR}/payload.txt"
if "${BASH}" "${TEMP_DIR}/install.sh" --verify-only >/dev/null 2>&1; then
  echo "test-offline-bundle: tampered bundle was accepted" >&2
  exit 1
fi

# Use the actual builder's checksum step. The nested manifest must be verified
# by the outer one, and the outer manifest cannot list a temporary self-entry.
STAGE="${TEMP_DIR}/stage"
PAYLOAD="${STAGE}/payload"
WORK_DIR="${TEMP_DIR}/outside"
mkdir -p "$PAYLOAD/dist" "$WORK_DIR"
VERSION=9.9.9
ARCH=amd64
printf 'payload\n' >"${STAGE}/payload.txt"
printf 'fixture package\n' >"$PAYLOAD/dist/easy-waf_${VERSION}_${ARCH}.deb"
cp "${SCRIPT_DIR}/install-offline-bundle.sh" "${STAGE}/install.sh"
checksum_step="$(sed -n '/^write_bundle_checksums() {$/,/^}$/p' "$SCRIPT_DIR/build-offline-bundle.sh")"
[[ -n "$checksum_step" ]] || { echo 'test-offline-bundle: builder checksum step missing' >&2; exit 1; }
eval "$checksum_step"
write_bundle_checksums
(cd "$PAYLOAD/dist" && sha256sum -c --quiet SHA256SUMS)
grep -qF '  ./payload/dist/SHA256SUMS' "${STAGE}/SHA256SUMS"
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

# The installer sources /etc/os-release before handing the package version
# to its payload. Exercise that handoff on its supported Ubuntu host.
if [[ "$EUID" == 0 ]] && (
  [[ -f /etc/os-release ]] || exit 1
  # shellcheck source=/dev/null
  . /etc/os-release
  [[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]]
); then
  mkdir -p "$STAGE/repository" "$PAYLOAD/scripts"
  : >"$STAGE/repository/Packages"
  printf 'EASY_WAF_BUNDLE_VERSION=%s\nEASY_WAF_BUNDLE_UBUNTU=24.04\nEASY_WAF_BUNDLE_ARCH=%s\nEASY_WAF_BUNDLE_CROWDSEC=0\n' \
    "$VERSION" "$(dpkg --print-architecture)" >"$STAGE/BUNDLE.env"
  cat >"$PAYLOAD/scripts/install.sh" <<'PAYLOAD'
set -eu
[[ "$EASY_WAF_RELEASE_VERSION" == 9.9.9 && "$EASY_WAF_OFFLINE" == 1 ]]
PAYLOAD
  cat >"$TEMP_DIR/handoff-fixture.env" <<'FIXTURE'
mkdir() {
  if [[ "$*" == '-p /var/cache/apt/archives/partial' ]]; then return 0; fi
  command mkdir "$@"
}
df() {
  printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\nfixture 8388608 0 8388608 0%% /\n'
}
FIXTURE
  write_bundle_checksums
  if ! BASH_ENV="$TEMP_DIR/handoff-fixture.env" "${BASH}" "$STAGE/install.sh" >/dev/null; then
    echo 'test-offline-bundle: wrong package version passed to the installer' >&2
    exit 1
  fi
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
  python3 -I "$SCRIPT_DIR/test-offline-crowdsec-snapshot.py"
  python3 -I "$SCRIPT_DIR/test-install-offline-crowdsec.py"
fi
echo "test-offline-bundle: PASS"
