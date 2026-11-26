# Offline bundle

The production offline artifact is a versioned ISO containing a local APT
repository, the Easy Home WAF Debian package, and the provisioning scripts. It
is built separately for Ubuntu 24.04 `amd64` and `arm64`.

The release workflow stages the signed packages and both signed ISOs in the
same Actions run. Before signing each ISO it extracts the image and compares
both copies of the Easy WAF DEB with the verified release package. It verifies
the complete set before creating a release.
GitHub CLI uploads the assets to a draft before publishing it. If an interrupted
upload leaves a draft, inspect it before retrying the workflow for that tag.

The ISO is more than a copy of `easy-waf_*.deb`. It contains the recursive
dependency closure for HAProxy, nftables, PostgreSQL, Fail2Ban, CrowdSec and the
HAProxy SPOA bouncer. The installer reads only the verified repository through
a temporary APT configuration with fresh package indexes. It skips the system
APT configuration files and their hooks. Package installation uses the host's
dpkg database, APT pinning preferences and archive cache.

## Download and verify

On a connected, trusted workstation, open the published release and download
these three files for the same tag and architecture. [GitHub Releases](https://github.com/sbezpalov/easy-waf/releases)

- `easy-waf_<version>_offline_ubuntu24.04_<arch>.iso`
- the matching `.iso.sha256`
- the matching `.iso.sigstore.json`

Set the version and architecture to match the downloaded files. Verify the
keyless signature against the exact release tag and then verify the checksum.
The certificate identity follows the policy in [SECURITY.md](SECURITY.md#supply-chain).

```bash
VERSION=1.6.1
ARCH=amd64
ISO="easy-waf_${VERSION}_offline_ubuntu24.04_${ARCH}.iso"
cosign verify-blob \
  --bundle "${ISO}.sigstore.json" \
  --certificate-identity "https://github.com/sbezpalov/easy-waf/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ISO" && sha256sum -c "${ISO}.sha256"
```

On macOS, replace the checksum command with `shasum -a 256 -c "${ISO}.sha256"`.
On Windows, run the following in PowerShell from the download directory, with
Cosign on `PATH`. Use the version and architecture of the appliance media.

```powershell
$version = '1.6.1'
$arch = 'amd64'
$iso = "easy-waf_${version}_offline_ubuntu24.04_${arch}.iso"
$identity = "https://github.com/sbezpalov/easy-waf/.github/workflows/release.yml@refs/tags/v${version}"
cosign verify-blob --bundle "$iso.sigstore.json" --certificate-identity $identity `
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' $iso
if ($LASTEXITCODE -ne 0) { throw 'ISO signature verification failed' }

$line = (Get-Content -LiteralPath "$iso.sha256" -Raw -ErrorAction Stop).TrimEnd("`r", "`n")
if ($line -cnotmatch ('^([0-9a-f]{64})  ' + [regex]::Escape($iso) + '$')) {
  throw 'Unexpected ISO checksum manifest entry'
}
$expected = $Matches[1]
$actual = (Get-FileHash -LiteralPath $iso -Algorithm SHA256 -ErrorAction Stop).Hash
if ($actual -ne $expected) { throw 'ISO checksum verification failed' }
Write-Output "Verified $iso"
```

Transfer the ISO across the air gap after both checks pass. The checksum file
detects transfer damage. Verify authenticity on a trusted connected workstation
or use a checksum delivered through another trusted channel.

## Install

Use an ISO built for the appliance's Ubuntu release and architecture. Published
1.6.1 images target Ubuntu 24.04. Locally built 26.04 candidate images have
`ubuntu26.04` in the filename. For an ISO copied to disk, substitute its exact
path in the example:

```bash
ISO="./easy-waf_1.6.1_offline_ubuntu24.04_amd64.iso"
sudo mkdir -p /mnt/easy-waf-offline
sudo mount -o loop,ro "$ISO" /mnt/easy-waf-offline
```

If the ISO is attached as virtual media, mount the optical device read-only
instead. Set the path below to its mount point:

```bash
cd /mnt/easy-waf-offline
bash install.sh --verify-only
sudo EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR=/mnt/private-media/crowdsec-snapshot bash install.sh
```

Mount the ISO or extract the archive to a directory of your choice. Quote the
path in shell commands if it contains spaces or other shell metacharacters.
After verifying the published image signature and checksum, use
`install.sh --verify-only` to verify the extracted file manifest, package
checksum and equality of the two Easy WAF package copies. This step needs
only read access to the bundle and does not invoke APT.

For a clean installation of the full profile from the public ISO, prepare a
[CrowdSec snapshot](#prepare-a-private-crowdsec-snapshot) on a connected host and
transfer it separately. Keep its checksum from the trusted preparation host
and verify the transferred files there or on the isolated appliance. The
snapshot contains Hub rules and data. The public ISO contains the CrowdSec
packages. The installer checks the snapshot files and CrowdSec version before
using them. An appliance with a configured CrowdSec agent can reuse that agent
without supplying a snapshot.

The private ISO already embeds the snapshot, so run `sudo bash install.sh`.
To install the base profile from public media on a clean host, use
`sudo EASY_WAF_INSTALL_CROWDSEC=0 bash install.sh`. The full-profile installer
reports a missing snapshot before provisioning the appliance.

The installer fails closed when an internal file is damaged, the host is not
running the Ubuntu release recorded in the bundle, the architecture differs,
or there is insufficient free space. It leaves the host's APT sources and
indexes intact. It removes its temporary APT
configuration and indexes on exit.

The ISO includes a local `payload/dist/SHA256SUMS` for the Easy WAF DEB.
The outer manifest also covers this file. Before modifying the host, the
installer checks the DEB against this inner checksum and checks its name,
version and architecture against the bundle metadata. It also checks that
the local APT repository contains an identical DEB. The offline installer
always uses that package. The source installer's binary selection variables
`EASY_WAF_DIST_DIR`, `EASY_WAF_INSTALL_FROM_PACKAGE` and
`EASY_WAF_SKIP_BINARY_FETCH` have no effect in this mode.

Provisioning overrides still apply. For example, an external database:

```bash
sudo EASY_WAF_INSTALL_POSTGRES=0 bash install.sh
```

After installation, follow the enrollment and smoke-test steps in
[`QUICKSTART.md`](QUICKSTART.md) and [`ACCEPTANCE.md`](ACCEPTANCE.md).

## Build locally

Build on a host matching the target Ubuntu release and architecture. For the
26.04 migration candidate, configure the signed HAProxy 3.4 repository on the
builder (see `scripts/testdata/install-haproxy-34-ci.sh`). The ISO filename
includes `ubuntu26.04`. The published 1.6.1 images target 24.04.
Configure the pinned CrowdSec repository using `scripts/lib/crowdsec-install.sh`,
then install the build tools:

```bash
sudo apt-get install apt-utils dpkg-dev xorriso
make deb
make offline-bundle
```

The builder asks APT, against an empty package status, for the concrete packages
a fresh system on the selected Ubuntu release would install. Virtual dependencies such as
`dbus-system-bus` and `libgnutls30` are stored as the provider APT selects
(`dbus`, `libgnutls30t64`), not as the virtual name.

Set `TMPDIR` to choose the temporary build volume. When the builder runs as
root, APT uses that volume if `_apt` can traverse the chosen directory.
With a private `TMPDIR`, the APT workspace falls back to `/tmp` and staging
stays in `TMPDIR`.

`EASY_WAF_OFFLINE_INCLUDE_CROWDSEC=0` builds a smaller base bundle. Its
installer defaults to the base profile and rejects requests to install the
absent CrowdSec packages.
`EASY_WAF_OFFLINE_FORMAT=tar.gz` is available for development; release artifacts
use the read-only ISO form. Production builds accept only committed inputs and
stage them from Git, so ignored or untracked local files cannot enter the image.

Every bundle includes `PACKAGE-MANIFEST.tsv` with the binary package, version,
architecture and source package fields. The Debian package metadata and license
texts remain inside each `.deb`; exact Ubuntu source packages are available from
the corresponding Ubuntu archive snapshot, and CrowdSec sources from its
upstream repository.

### Prepare a private CrowdSec snapshot

On a connected Ubuntu build host, run the following with `cscli` from the same
CrowdSec version as the target DEB:

```bash
bash scripts/prepare-offline-crowdsec.sh /path/to/new-snapshot
```

The parent directory must already exist. The tool uses a temporary CrowdSec
configuration, downloads the Hub cache and data for the Linux, HAProxy, SSH
and PostgreSQL collections, and writes the selection, CLI version, branch and
SHA-256 manifest alongside them. The cache contains GeoLite data and is intended for
private use under the applicable [MaxMind terms](https://www.maxmind.com/en/geolite/eula).

To include a prepared snapshot in a private evaluation image on Ubuntu,
use `EASY_WAF_OFFLINE_CROWDSEC_SNAPSHOT_DIR=/path/to/new-snapshot` with
`scripts/build-offline-bundle.sh`. The builder requires Python 3 for
this option and checks the snapshot against the selected CrowdSec DEB.
The image contains the verified files under `payload/crowdsec-snapshot`
and its filename ends in `_private.iso`.

The private ISO installer requires Python 3 on the appliance. On a clean
host it configures the bundled CrowdSec package with a local API, serves the
verified Hub index over loopback during setup, and enables the Linux,
HAProxy, SSH and PostgreSQL collections from the cache. It disables the
vendor Hub refresh timer on this installation. For an interrupted bootstrap,
rerun the same private ISO to resume with the same snapshot. A configured
CrowdSec agent already present on the host keeps its package version and
Hub configuration during this step.

## Updates and support boundary

The newest verified bundle delivers updates for Easy WAF, HAProxy, PostgreSQL
and the security stack together. Ubuntu 24.04 is the published baseline for
1.6.1. The installer also accepts locally built Ubuntu 26.04 candidates on
matching hosts. Each bundle requires its recorded Ubuntu release and
architecture. A 26.04 candidate requests HAProxy 3.4 from its local APT
repository during installation and updates, including when another HAProxy
branch is already installed.

For rollback, restore a pre-upgrade backup or install the previous verified ISO.
Database migrations may make package-only downgrades unsafe; read that release's
upgrade notes and use [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md).
