# Offline bundle

The production offline artifact is a versioned ISO containing a local APT
repository, the Easy Home WAF Debian package, and the provisioning scripts. It
is built separately for Ubuntu 24.04 `amd64` and `arm64`.

The ISO is more than a copy of `easy-waf_*.deb`. It contains the recursive
dependency closure for HAProxy, nftables, PostgreSQL, Fail2Ban, CrowdSec and the
HAProxy SPOA bouncer. During installation APT is configured through a temporary
`APT_CONFIG` to see only that verified repository. Existing online sources are
not edited and cannot affect package resolution.

## Download and verify

Download these three files for the same release and architecture on a connected,
trusted workstation:

- `easy-waf_<version>_offline_ubuntu24.04_<arch>.iso`
- the matching `.iso.sha256`
- the matching `.iso.sigstore.json`

First verify the keyless signature using the same GitHub Actions identity policy
as [`SECURITY.md`](SECURITY.md#supply-chain), then verify the ISO checksum:

```bash
cosign verify-blob \
  --bundle easy-waf_1.6.0_offline_ubuntu24.04_amd64.iso.sigstore.json \
  --certificate-identity-regexp '^https://github.com/sbezpalov/easy-waf/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  easy-waf_1.6.0_offline_ubuntu24.04_amd64.iso
sha256sum -c easy-waf_1.6.0_offline_ubuntu24.04_amd64.iso.sha256
```

Transfer the verified ISO across the air gap. The checksum file is useful for
detecting transfer damage, but authenticity comes from verification on a trusted
connected workstation (or from a checksum delivered through another trusted
channel).

## Install

Attach the ISO as virtual media or copy it to the Ubuntu 24.04 appliance, then:

```bash
sudo mkdir -p /mnt/easy-waf-offline
sudo mount -o loop,ro easy-waf_1.6.0_offline_ubuntu24.04_amd64.iso /mnt/easy-waf-offline
cd /mnt/easy-waf-offline
bash install.sh --verify-only
sudo bash install.sh
```

The installer fails closed when an internal file is damaged, the host is not
Ubuntu 24.04, the architecture differs, or there is insufficient free space. It
does not modify `/etc/apt/sources.list*`; the local-only APT configuration exists
only for the installer process.

All normal installer overrides still apply. For example, an external database:

```bash
sudo EASY_WAF_INSTALL_POSTGRES=0 bash install.sh
```

After installation, follow the enrollment and smoke-test steps in
[`QUICKSTART.md`](QUICKSTART.md) and [`ACCEPTANCE.md`](ACCEPTANCE.md).

## Build locally

Build on a native-architecture Ubuntu 24.04 host. Configure the pinned CrowdSec
repository using `scripts/lib/crowdsec-install.sh`, then install the build tools:

```bash
sudo apt-get install apt-utils dpkg-dev xorriso
make deb
make offline-bundle
```

The builder asks APT, against an empty package status, for the concrete packages
a fresh Ubuntu 24.04 system would install. Virtual dependencies such as
`dbus-system-bus` and `libgnutls30` are stored as the provider APT selects
(`dbus`, `libgnutls30t64`), not as the virtual name.

`EASY_WAF_OFFLINE_INCLUDE_CROWDSEC=0` builds a smaller base bundle, but that is
not the default appliance profile; its installer automatically disables the
CrowdSec provisioning step unless the operator explicitly overrides it.
`EASY_WAF_OFFLINE_FORMAT=tar.gz` is available for development; release artifacts
use the read-only ISO form. Production builds accept only committed inputs and
stage them from Git, so ignored or untracked local files cannot enter the image.

Every bundle includes `PACKAGE-MANIFEST.tsv` with the binary package, version,
architecture and source package fields. The Debian package metadata and license
texts remain inside each `.deb`; exact Ubuntu source packages are available from
the corresponding Ubuntu archive snapshot, and CrowdSec sources from its
upstream repository.

## Updates and support boundary

An offline ISO is a frozen package snapshot. Install the newest verified bundle,
not merely the newest Easy WAF `.deb`, so HAProxy, PostgreSQL and the security
stack receive their available updates too. The supported baseline is Ubuntu
24.04 on the matching architecture; arbitrary derivative distributions and
cross-release upgrades are outside the bundle contract.

For rollback, restore a pre-upgrade backup or install the previous verified ISO.
Database migrations may make package-only downgrades unsafe; read that release's
upgrade notes and use [`BACKUP_RESTORE.md`](BACKUP_RESTORE.md).
