# Deployment: Ubuntu 24.04 LTS — Deployment, OVF/OVA, Distribution

**Version:** root [`VERSION`](../VERSION) (**1.4.0** for the current release); the installer uses it when fetching release artifacts. Artifacts are checked against `SHA256SUMS` from the same release before anything is unpacked — see [SECURITY.md](SECURITY.md#supply-chain).

## Development (Windows) vs deployment (Linux)

Typical workflow for this project:

| Phase | Environment | Notes |
|-------|-------------|--------|
| **Development** | **Windows 11** (local PC, IDE) | Use **Git Bash** or **WSL** to run the same checks as CI (`make ci`, `bash scripts/check-linux-artifacts.sh`). Avoid CRLF in `scripts/**/*.sh`; keep paths Linux-oriented in configs and docs. |
| **CI / QA** | **GitHub Actions** (`ubuntu:24.04` container) | Same Go/lint/shell checks as on the pilot host. |
| **Production** | **Ubuntu 24.04 LTS** (`apt`) | Debian 12+ may work (same `apt` installer) but is **not** tested in CI. Layout: `/var/lib/easy-waf`, `/etc/easy-waf`, systemd. |

The **source of truth** for “will it ship?” is what passes on **Linux**, not only ad-hoc commands in PowerShell without `bash`/`go`.

Setting up a Linux host for development and pre-release testing: see **[DEV_HOST.md](DEV_HOST.md)**.

## What the installer does

[`scripts/install.sh`](../scripts/install.sh) (run as **root**):

1. Creates user `easy-waf` and directory layout under `EASY_WAF_STATE_DIR` (default `/var/lib/easy-waf`): `haproxy/`, `revisions/`, `certs/`, `acme/webroot`, `secrets/` (0700).
2. **Installs the `easy-waf` Debian package** for the version in [`VERSION`](../VERSION) — downloaded from the matching GitHub release and verified against `SHA256SUMS`, then `apt install`ed. The package owns `/usr/sbin/easy-waf-{api,acmed,hostd,admin}`, `/usr/sbin/easy-waf-diagnostics`, the units in `/lib/systemd/system/`, and `/etc/easy-waf/easy-waf.env` as a **conffile**. Fallback order and the `EASY_WAF_BUILD_FROM_SOURCE` opt-in: [ADR 0001](adr/0001-packaging-and-installer.md).
3. Only when the package was not used: copies binaries from `dist/` (or `EASY_WAF_DIST_DIR`), copies [`configs/defaults/easy-waf.env.example`](../configs/defaults/easy-waf.env.example) to `/etc/easy-waf/easy-waf.env` if missing, and installs **systemd** units from `packaging/systemd/` into `/etc/systemd/system/` (unless `EASY_WAF_SKIP_SYSTEMD=1`). Units left in `/etc/systemd/system/` by an earlier script install are renamed to `*.replaced-by-package` when the package takes over, because `/etc` overrides `/lib` and would silently keep the old definition.
4. Optionally (`EASY_WAF_INSTALL_OS_PACKAGES=1`) installs base packages via **apt** (Ubuntu 24.04+): HAProxy, **nftables**, fail2ban, netplan, CA certs. **PostgreSQL server defaults on** (`EASY_WAF_INSTALL_POSTGRES` defaults to **1**); set **`EASY_WAF_INSTALL_POSTGRES=0`** when using an external database only.
5. After `/etc/easy-waf/easy-waf.env` exists, when local PostgreSQL was installed: **prepends** [`scripts/lib/pg-hba-easywaf.sh`](../scripts/lib/pg-hba-easywaf.sh) rules so TCP `127.0.0.1` uses **scram-sha-256** for `easywaf` (ensures password auth for `DATABASE_URL`), **creates** role and database `easywaf`, and may **rotate** weak default passwords (see [`scripts/lib/db-password.sh`](../scripts/lib/db-password.sh)).
6. Optionally **`EASY_WAF_ENABLE_SYSTEMD_UNITS=0`** skips `systemctl enable --now` at the end (default is to **start** services).
7. **CrowdSec + SPOA bouncer (default on apt):** installs packages from packagecloud so units exist; **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`** (or **`scripts/crowdsec-bootstrap-lapi.sh`**) starts LAPI, registers bouncers, writes **`CROWDSEC_LAPI_*`** (see [CROWDSEC.md](CROWDSEC.md)). Set **`EASY_WAF_INSTALL_CROWDSEC=0`** to skip packages entirely.
8. **AppArmor:** no special profiles needed for HAProxy on Ubuntu (stock policy sufficient). Access to generated configs uses **Unix group membership** (`haproxy` in group `easy-waf`) and file permissions.
9. **nftables:** with OS packages, writes **`/etc/nftables/easy-waf.nft`**, opens **management** ports (**8000/8443**) from RFC1918 + loopback only (when **`EASY_WAF_NFT_MGMT_LAN=1`**) and **HAProxy edge** (**80/tcp** + **443/tcp**) when **`EASY_WAF_NFT_EDGE=1`** (default). Already-deployed hosts: **`sudo bash scripts/fix-nftables-edge.sh`**.

CrowdSec is part of the default appliance install; see [CROWDSEC.md](CROWDSEC.md) for **`EASY_WAF_INSTALL_CROWDSEC`**, **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL`**, and **`scripts/crowdsec-bootstrap-lapi.sh`**.

## Ubuntu 24.04 LTS (bare metal / VM)

1. Clone the repo on the target host (or unpack a source tree). Run **`sudo bash scripts/install.sh`** — by default it **installs OS packages** (`EASY_WAF_INSTALL_OS_PACKAGES` defaults to **1**), **acquires binaries** from the **GitHub release** matching [`VERSION`](../VERSION) / `EASY_WAF_RELEASE_VERSION` — the `.deb` first, then the tarball, each verified against `SHA256SUMS`. If neither verifies it **stops** rather than compiling here; `EASY_WAF_BUILD_FROM_SOURCE=1` opts into a source build (which installs Go, make and git on this host and leaves them). Minimal footprint: `EASY_WAF_INSTALL_OS_PACKAGES=0`. Pre-built only: `EASY_WAF_SKIP_BINARY_FETCH=1 EASY_WAF_DIST_DIR=/path/to/dist`. Published releases: [`scripts/download-release.sh`](../scripts/download-release.sh).
2. **Recommended (interactive, LAN-only API + optional CrowdSec):** `sudo bash scripts/install-interactive.sh`  
   **Or minimal:** `sudo bash scripts/install.sh` (same as [QUICKSTART.md](QUICKSTART.md): local PostgreSQL + DB provisioning + start services by default).
3. **External database only:** `sudo EASY_WAF_INSTALL_POSTGRES=0 bash scripts/install.sh`, edit `/etc/easy-waf/easy-waf.env` (`DATABASE_URL`), then `sudo systemctl enable --now easy-waf-api easy-waf-acmed` (or use `EASY_WAF_ENABLE_SYSTEMD_UNITS=0` on install and start after editing).
4. If CrowdSec packages were skipped (**`EASY_WAF_INSTALL_CROWDSEC=0`**) or LAPI was not bootstrapped: run **`sudo bash scripts/crowdsec-bootstrap-lapi.sh`** or **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1 bash scripts/install.sh`** per [CROWDSEC.md](CROWDSEC.md).

Requirements:

- **root** (or `sudo`)
- **`apt-get`** available (Ubuntu 24.04 LTS recommended)
- **systemd** (default on Ubuntu Server)

## PostgreSQL password on first install

If **local PostgreSQL** is installed and `DATABASE_URL` still uses the example passwords **`easywaf:secret`** or **`easywaf:easywaf`**, **`scripts/lib/db-password.sh`** runs **`ALTER USER easywaf`** and rewrites **`DATABASE_URL`** with a random hex password (unless `EASY_WAF_ROTATE_WEAK_DB_PASSWORD=0`). Always use a strong password for external databases.

If you see **`Ident authentication failed for user "easywaf"`**, run **`sudo bash scripts/lib/pg-hba-easywaf.sh`** (or re-run **`install.sh`**) — see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## OVF / OVA (appliance image)

**Recommended bake into the template:**

| Layer | Suggestion |
|-------|------------|
| OS | Ubuntu 24.04 LTS (server, minimal) + updates |
| Packages | `haproxy`, `nftables`, `fail2ban`, `postgresql` *or* leave DB external |
| Binaries | Pre-place `easy-waf-api`, `easy-waf-acmed` in `/usr/sbin/` from CI build |
| systemd | Pre-enable `nftables`, `fail2ban`; **do not** auto-enable `easy-waf-*` until first-boot config |
| First boot | cloud-init / autoinstall: write `/etc/easy-waf/easy-waf.env` from metadata, `systemctl enable --now easy-waf-api easy-waf-acmed` |
| Secrets | **Never** bake real `DATABASE_URL` or `EASY_WAF_ADMIN_TOKEN` into the image — inject at deploy time |
| Disk | Separate `/var/lib/easy-waf` for certs and generated configs (snapshot-friendly) |

**VM sizing (ESXi / QEMU–KVM):** see **[VM-REQUIREMENTS.md](VM-REQUIREMENTS.md)** — vCPU, RAM, disk, and NIC/controller choices.

See [packaging/ovf/README.md](../packaging/ovf/README.md) for a minimal checklist.

## Release artifacts (for `download-release.sh`)

Automated GitHub Release build and publish: workflow **[`.github/workflows/release.yml`](../.github/workflows/release.yml)** (trigger — push of tag `v*`: `make build`, tarball, `SHA256SUMS`, release notes from the matching [`CHANGELOG.md`](../CHANGELOG.md) section).

**Which repository artifacts come from:** `install.sh` and `download-release.sh` derive `owner/name` from the **origin remote of the checkout they run from**, falling back to `easy-waf/easy-waf`. Override with **`EASY_WAF_GITHUB_REPO`** (installer) or **`GITHUB_REPOSITORY`** (download script). This matters on a fork or after a rename: with a wrong repository every download 404s. Before 1.3.0 the installer then quietly built from source, which also meant the `SHA256SUMS` verification never ran; since 1.4.0 it stops and says so instead.

A release publishes **three** assets: `easy-waf_<version>_amd64.deb` (the primary
install and upgrade path), `easy-waf_<version>_linux_amd64.tar.gz` (binaries for
developers and manual placement), and `SHA256SUMS` covering both.

Archive `easy-waf_<version>_linux_amd64.tar.gz` contains:

```
dist/easy-waf-api
dist/easy-waf-acmed
dist/easy-wafd
dist/easy-waf-admin
packaging/systemd/*.service
configs/defaults/easy-waf.env.example
```

When unpacking into `repo/dist/`, **`scripts/install.sh`** and **`scripts/download-release.sh`** hoist binaries from the nested `dist/` folder into the target `dist/` root so paths match `make build`.

## Upgrades

**Package path (preferred).** Back up first ([BACKUP_RESTORE.md](BACKUP_RESTORE.md)), then:

```bash
curl -fLO https://github.com/sbezpalov/easy-waf/releases/download/vX.Y.Z/easy-waf_X.Y.Z_amd64.deb
curl -fLO https://github.com/sbezpalov/easy-waf/releases/download/vX.Y.Z/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
sudo apt install ./easy-waf_X.Y.Z_amd64.deb
sudo bash scripts/smoke-appliance.sh
```

`postinst` restarts **only the units that were already running**, so a
deliberately stopped service stays stopped. Database migrations still run when
the API starts. Your `/etc/easy-waf/easy-waf.env` is preserved: dpkg treats it as
a conffile, and if a release changes the shipped default you get a prompt with
the usual `Y/I/N/O/D/Z` options rather than a silent overwrite.

**Rollback** is `apt install ./easy-waf_<previous>_amd64.deb`, with the caveats
that already apply to any downgrade: additive migration columns are not removed,
so an older binary must tolerate them — check the upgrade note in
[`CHANGELOG.md`](../CHANGELOG.md) for the version you are leaving.

**Removal.** `apt remove` deletes binaries and units and leaves configuration and
state; `apt purge` additionally deletes `/etc/easy-waf`. Neither touches
`/var/lib/easy-waf` (TLS keys, certificates, revisions, JWT secret), the
PostgreSQL database, or the nftables policy — `postrm` prints how to remove the
state directory once you are sure. See [OPERATIONS.md](OPERATIONS.md).

**Script path (no package).** [`scripts/upgrade.sh`](../scripts/upgrade.sh) takes a
directory or `.tar.gz` of new binaries; it reuses `install.sh` and restarts units.
