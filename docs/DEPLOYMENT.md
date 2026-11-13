# Deployment: Ubuntu 24.04 LTS — Deployment, OVF/OVA, Distribution

**Tree version:** root [`VERSION`](../VERSION) (**1.6.1**); the installer uses it when fetching release artifacts. `main` can be ahead of the latest published GitHub Release, so use a release tag or set `EASY_WAF_RELEASE_VERSION` when installing a published version. Artifacts are checked against `SHA256SUMS` from the same release before anything is unpacked — see [SECURITY.md](SECURITY.md#supply-chain).

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
2. **Installs the `easy-waf` Debian package** for the version in [`VERSION`](../VERSION) — downloaded from the matching GitHub release and verified against `SHA256SUMS`, then `apt install`ed. The package owns `/usr/sbin/easy-waf-{api,acmed,hostd,admin}`, `/usr/sbin/easy-waf-diagnostics`, the units in `/lib/systemd/system/`, and `/etc/easy-waf/easy-waf.env` as a **conffile**. Fallback order and the `EASY_WAF_BUILD_FROM_SOURCE` opt-in: [ADR 0001](adr/0001-packaging-and-installer.md). Set **`EASY_WAF_INSTALL_FROM_PACKAGE=0`** to skip the `.deb` entirely and take the tarball path instead (default `1`).
3. Only when the package was not used: copies binaries from `dist/` (or `EASY_WAF_DIST_DIR`), copies [`configs/defaults/easy-waf.env.example`](../configs/defaults/easy-waf.env.example) to `/etc/easy-waf/easy-waf.env` if missing, and installs **systemd** units from `packaging/systemd/` into `/etc/systemd/system/` (unless `EASY_WAF_SKIP_SYSTEMD=1`). Units left in `/etc/systemd/system/` by an earlier script install are renamed to `*.replaced-by-package` when the package takes over, because `/etc` overrides `/lib` and would silently keep the old definition.
4. Optionally (`EASY_WAF_INSTALL_OS_PACKAGES=1`) installs base packages via **apt** (Ubuntu 24.04+): HAProxy, **nftables**, fail2ban, netplan, CA certs. **PostgreSQL server defaults on** (`EASY_WAF_INSTALL_POSTGRES` defaults to **1**); set **`EASY_WAF_INSTALL_POSTGRES=0`** when using an external database only.
5. After `/etc/easy-waf/easy-waf.env` exists, when local PostgreSQL was installed: **prepends** [`scripts/lib/pg-hba-easywaf.sh`](../scripts/lib/pg-hba-easywaf.sh) rules so TCP `127.0.0.1` uses **scram-sha-256** for `easywaf` (ensures password auth for `DATABASE_URL`), **creates** role and database `easywaf`, and may **rotate** weak default passwords (see [`scripts/lib/db-password.sh`](../scripts/lib/db-password.sh)).
6. Optionally **`EASY_WAF_ENABLE_SYSTEMD_UNITS=0`** skips `systemctl enable --now` at the end (default is to **start** services).
7. **CrowdSec + SPOA bouncer (default on apt):** installs packages from packagecloud so units exist; **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`** (or **`scripts/crowdsec-bootstrap-lapi.sh`**) starts LAPI, registers bouncers, writes **`CROWDSEC_LAPI_*`** (see [CROWDSEC.md](CROWDSEC.md)). Set **`EASY_WAF_INSTALL_CROWDSEC=0`** to skip packages entirely.
8. **AppArmor:** no special profiles needed for HAProxy on Ubuntu (stock policy sufficient). Access to generated configs uses **Unix group membership** (`haproxy` in group `easy-waf`) and file permissions.
9. **nftables:** with OS packages, writes **`/etc/nftables/easy-waf.nft`**, opens **management** ports (**8000/8443**) from RFC1918 + loopback only (when **`EASY_WAF_NFT_MGMT_LAN=1`**) and **HAProxy edge** (**80/tcp** + **443/tcp** + **443/udp** for HTTP/3/QUIC) when **`EASY_WAF_NFT_EDGE=1`** (default). Already-deployed hosts: **`sudo bash scripts/fix-nftables-edge.sh`** (re-run after enabling HTTP/3 so UDP 443 is open).

CrowdSec is part of the default appliance install; see [CROWDSEC.md](CROWDSEC.md) for **`EASY_WAF_INSTALL_CROWDSEC`**, **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL`**, and **`scripts/crowdsec-bootstrap-lapi.sh`**.

## Ubuntu 24.04 LTS (bare metal / VM)

1. Clone the repo on the target host (or unpack a source tree). Run **`sudo bash scripts/install.sh`** — by default it **installs OS packages** (`EASY_WAF_INSTALL_OS_PACKAGES` defaults to **1**), **acquires binaries** from the **GitHub release** matching [`VERSION`](../VERSION) / `EASY_WAF_RELEASE_VERSION` — the `.deb` first, then the tarball, each verified against `SHA256SUMS`. If neither verifies it **stops** rather than compiling here; `EASY_WAF_BUILD_FROM_SOURCE=1` opts into a source build (which installs Go, make and git on this host and leaves them). Minimal footprint: `EASY_WAF_INSTALL_OS_PACKAGES=0`. Pre-built only: `EASY_WAF_SKIP_BINARY_FETCH=1 EASY_WAF_DIST_DIR=/path/to/dist`. Published releases: [`scripts/download-release.sh`](../scripts/download-release.sh).
2. **Recommended (interactive, LAN-only API + optional CrowdSec):** `sudo bash scripts/install-interactive.sh`  
   **Or minimal:** `sudo bash scripts/install.sh` (same as [QUICKSTART.md](QUICKSTART.md): local PostgreSQL + DB provisioning + start services by default).
3. **External database only:** `sudo EASY_WAF_INSTALL_POSTGRES=0 bash scripts/install.sh`, edit `/etc/easy-waf/easy-waf.env` (`DATABASE_URL`), then `sudo systemctl enable --now easy-waf-hostd easy-waf-api easy-waf-acmed` (or use `EASY_WAF_ENABLE_SYSTEMD_UNITS=0` on install and start after editing).
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
| Binaries | Pre-place `easy-waf-api`, `easy-waf-acmed`, `easy-waf-hostd`, `easy-waf-admin` in `/usr/sbin/` from CI build — or, simpler, pre-install the `.deb` |
| systemd | Pre-enable `nftables`, `fail2ban`; **do not** auto-enable `easy-waf-*` until first-boot config |
| First boot | cloud-init / autoinstall: write `/etc/easy-waf/easy-waf.env` from metadata, `systemctl enable --now easy-waf-hostd easy-waf-api easy-waf-acmed` |
| Secrets | **Never** bake real `DATABASE_URL` or `EASY_WAF_ADMIN_TOKEN` into the image — inject at deploy time |
| Disk | Separate `/var/lib/easy-waf` for certs and generated configs (snapshot-friendly) |

**VM sizing (ESXi / QEMU–KVM):** see **[VM-REQUIREMENTS.md](VM-REQUIREMENTS.md)** — vCPU, RAM, disk, and NIC/controller choices.

See [packaging/ovf/README.md](../packaging/ovf/README.md) for a minimal checklist.

## Release artifacts (for `download-release.sh`)

Automated GitHub Release build and publish: workflow **[`.github/workflows/release.yml`](../.github/workflows/release.yml)** (trigger — push of tag `v*`: `make build`, `make deb`, tarball, `SHA256SUMS` signed with cosign, release notes from the matching [`CHANGELOG.md`](../CHANGELOG.md) section).

**Which repository artifacts come from:** `install.sh` and `download-release.sh` derive `owner/name` from the **origin remote of the checkout they run from**, falling back to `easy-waf/easy-waf`. Override with **`EASY_WAF_GITHUB_REPO`** (installer) or **`GITHUB_REPOSITORY`** (download script). This matters on a fork or after a rename: with a wrong repository every download 404s. Before 1.3.0 the installer then quietly built from source, which also meant the `SHA256SUMS` verification never ran; since 1.4.0 it stops and says so instead.

From the next tag, a release publishes **six** assets: `easy-waf_<version>_amd64.deb` and `easy-waf_<version>_arm64.deb` (the install and upgrade path; `install.sh` picks the machine's architecture), `easy-waf_<version>_linux_amd64.tar.gz` and `easy-waf_<version>_linux_arm64.tar.gz` (binaries for developers and manual placement), `SHA256SUMS` covering all four, and its cosign signature `SHA256SUMS.sigstore.json`. A tag with `-` (`v1.7.0-rc.1`) is published as a pre-release, not the latest release.

The release already published as **1.6.0** has only the amd64 `.deb` and the amd64 tarball. arm64 files appear with the next tag, not by rewriting 1.6.0.

Both tarballs contain the same layout:

```
dist/easy-waf-api
dist/easy-waf-acmed
dist/easy-waf-hostd
dist/easy-wafd
dist/easy-waf-admin
packaging/systemd/*.service
packaging/systemd/haproxy-easy-waf-dropin.conf
configs/defaults/easy-waf.env.example
configs/defaults/haproxy-bootstrap.cfg
scripts/fix-haproxy-easy-waf-dropin.sh
scripts/lib/selinux-easy-waf-haproxy.sh
LICENSE
NOTICE
```

Place **`easy-waf-hostd`** too. It is the root broker, and without it every
privileged feature — host updates, fail2ban, nftables, netplan, local users —
fails at the socket. (`easy-wafd` is the legacy alias; the package deliberately
omits it and you should not enable a unit for it.)

When unpacking into `repo/dist/`, **`scripts/install.sh`** and **`scripts/download-release.sh`** hoist binaries from the nested `dist/` folder into the target `dist/` root so paths match `make build`.

## Upgrades

**Package path (preferred).** Back up first ([BACKUP_RESTORE.md](BACKUP_RESTORE.md)). From a release-tag checkout, with `cosign` on `PATH`, download and authenticate the package through the shared verifier before giving it to `apt`:

```bash
VERSION=X.Y.Z
ARCH="$(dpkg --print-architecture)"
NAME="easy-waf_${VERSION}_${ARCH}.deb"
BASE="https://github.com/sbezpalov/easy-waf/releases/download/v${VERSION}"
source scripts/lib/release-verify.sh
easy_waf_curl_https -o "$NAME" "$BASE/$NAME"
easy_waf_verify_release_artifact "$NAME" "$NAME" "$BASE/SHA256SUMS"
sudo apt install "./$NAME"
sudo bash scripts/smoke-appliance.sh
```

The verifier checks the artifact digest only after authenticating `SHA256SUMS.sigstore.json` against this repository's `release.yml` identity. A checksum file downloaded beside the package is not provenance by itself. The explicit `EASY_WAF_ALLOW_UNSIGNED_SUMS=1` downgrade is for controlled mirrors and is not the preferred production path.

`postinst` installs the polkit rule into `/etc/polkit-1/rules.d/` (so Apply can
reload HAProxy) and the HAProxy systemd drop-in under
`/etc/systemd/system/haproxy.service.d/easy-waf.conf` (unprivileged master on
the generated config). It restarts **only the units that were already running**,
so a deliberately stopped service stays stopped. API/acmed restarts are queued
with `try-restart --no-block`, so ACME's graceful stop (up to 50 minutes) cannot
hold dpkg past the parent APT's 30-minute budget;
APT-worker/broker restart is queued in `easy-waf-hostd-restart.service`, outside
both owning cgroups. That root helper first reserves the private execution lease,
then waits for the real APT frontend and dpkg backend locks. It holds all three
across `systemctl try-restart easy-waf-apt.service easy-waf-hostd.service`, so a
new worker transaction cannot enter during maintenance.
It cannot kill the package transaction configuring Easy WAF, including when
the running broker is an older binary. It never creates/deletes those lock files
or weakens the broker's systemd kill policy. A scheduling/inspection/lock timeout
failure leaves the old broker running and requires operator attention; there
is no immediate-restart fallback. Lock acquisition has 32 minutes, followed by
a separate two-minute restart-command budget and cleanup allowance within the
35-minute helper budget. An expiring lock-wait deadline cannot cut short a
newly submitted restart job's wait.
Interrupt/TERM cancels acquisition; after job submission the helper finishes
the bounded wait before releasing locks. Its own service uses mixed termination
and a three-minute stop allowance for that wait; the broker's kill policy is
unchanged.

The packaged `/etc/needrestart/conf.d/easy-waf-hostd.conf` conffile excludes the
four managed static Go processes from automatic `needrestart` selection:
Ubuntu 24.04 runs that hook inside APT, so it must not bypass the package's
APT-owner coordination or wait on the queued ACME drain. All other services keep
their existing restart policy. The source installer installs the
same policy. The maintenance unit is not enabled at boot and has no ordering
dependency on worker/broker (its command synchronously waits for their jobs).
Each package configuration uses `restart --no-block` on that helper, refreshing
an earlier request even if the previous oneshot is just finishing. This is safe
inside dpkg: its lock prevents the earlier helper from concurrently owning both
locks and running a protected restart.

`easy-waf-apt.service` is an internal root daemon using the same hostd executable.
Broker starts it through Wants/After and waits for socket readiness. Only root
can use its private socket; the public API still calls broker and keeps the
existing HTTP/JSON/NDJSON protocol. Broker stop/crash cannot kill its APT child
or erase that worker's selected operation/result. If the worker is unavailable,
APT requests fail explicitly; they never execute in the broker as fallback.
See [ADR 0008](adr/0008-apt-execution-service.md).

Database migrations still run
when the API starts: only those not yet in `schema_migrations`, each in one
transaction, so a failed migration leaves the schema as it was. Your
`/etc/easy-waf/easy-waf.env` is preserved: dpkg treats it as a conffile, and if a
release changes the shipped default you get a prompt with the usual
`Y/I/N/O/D/Z` options rather than a silent overwrite.

After a package-only upgrade, confirm:

```bash
test -f /etc/polkit-1/rules.d/99-easy-waf-haproxy.rules
systemctl cat haproxy.service | grep -F /var/lib/easy-waf/haproxy/haproxy.cfg
systemctl show easy-waf-hostd-restart.service -p ActiveState -p Result -p ExecMainStartTimestamp -p ExecMainExitTimestamp
journalctl -u easy-waf-hostd-restart.service -n 40 --no-pager
sudo bash scripts/smoke-appliance.sh
```

The queued job can remain `activating` while package work finishes. A successful
oneshot ends `inactive` with `Result=success`; `failed` requires investigation.
After resolving a failure and finishing package work, run
`sudo systemctl start easy-waf-hostd-restart.service` and check its result again.
Do not remove package lock files. When upgrading through the panel, API restart
can interrupt its stream; reopen System to observe the current operation/log.
After restarting the APT worker itself, its prior in-memory result can be lost;
inspect the retained log and package state if the selected run is unavailable.
Package removal stops queued maintenance and asynchronously drains the APT
owner, allowing it to finish its own removal transaction before exiting.
API/ACME restarts may still be pending; confirm their final service state before
accepting the upgrade. A draining issuance is allowed to finish before the new
ACME process starts.

The automated lifecycle check is `make test-package-restart-e2e` (or
`bash scripts/test-package-restart-e2e.sh` in Git Bash on Windows or a macOS/Linux
shell). It builds a disposable Ubuntu 24.04 systemd image and Linux Go binaries.
Docker must support a private cgroup namespace, delegated writable container
cgroups, `SYS_ADMIN` for the units' mount namespaces and `SYS_PTRACE` for broker
verification of the real test API UID/executable inside its private PID namespace.
The fixture uses no
privileged mode, writable host mounts or runtime network. Only its own container,
temporary binaries and image tag are removed. Image construction can download
Ubuntu packages; `EASY_WAF_PACKAGE_E2E_IMAGE` selects an already built fixture
image, and `EASY_WAF_PACKAGE_E2E_BASE_IMAGE` selects its Ubuntu 24.04 base.
`GO_BIN` and `DOCKER_BIN` can point to existing executables outside `PATH`.

This test uses the production broker/worker binary and units, complete
postinst/prerm and real APT/dpkg against a local fixture package repository. It
proves an owner-cgroup negative control, exclusion while locks are held, restart
after release, nonblocking ACME drain, stopped-service preservation, real API
identity denial at the worker, broker stop/SIGKILL survival and removal of the
running APT owner's own package. API/ACME workers are fixture processes;
the minimal package intentionally omits appliance dependencies, database,
certificates and network provisioning. Full appliance install/upgrade acceptance
in [ACCEPTANCE.md](ACCEPTANCE.md) remains a separate check.

**Rollback** is `apt install --allow-downgrades ./easy-waf_<previous>_amd64.deb`.
Without the flag `apt` refuses. When the older build has no independent APT
service, first finish current
package work and stop `easy-waf-apt.service` from a separate root/SSH shell.
Run that downgrade through external APT, so removing the worker unit does not
leave an unused running process. Its operation log/state is retained.
Below 1.5.0 the edge keeps serving its current
config, but every Apply then fails `haproxy -c` while an application has CrowdSec
on, because those releases do not match the bouncer's SPOE config. Turn CrowdSec
off on those applications to apply changes. The caveats that apply to any
downgrade: additive migration columns are not removed,
so an older binary must tolerate them (it logs that the schema is newer than it
knows and keeps running) — check the upgrade note in
[`CHANGELOG.md`](../CHANGELOG.md) for the version you are leaving.

**Removal.** `apt remove` deletes binaries and units and leaves configuration and
state; `apt purge` additionally deletes the `easy-waf.env` conffile and removes
`/etc/easy-waf` **if nothing else is left in it**. Neither touches
`/var/lib/easy-waf` (TLS keys, certificates, revisions, JWT secret), the
PostgreSQL database, or the nftables policy — `postrm` prints how to remove the
state directory once you are sure. See [OPERATIONS.md](OPERATIONS.md).

**Script path (no package).** [`scripts/upgrade.sh`](../scripts/upgrade.sh) takes a
directory or `.tar.gz` of new binaries; it flattens a nested `dist/` from the
release tarball (and fails if `easy-waf-api` is still missing), reuses
`install.sh`, waits through the same lock-protected broker helper after its own
package work finishes, and queues active **api** and **acmed** restarts. It does not cancel an
already running maintenance helper to restart the broker.
