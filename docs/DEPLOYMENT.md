# Deployment: AlmaLinux / Debian-family, OVF/OVA, distribution

**Версия:** корневой [`VERSION`](../VERSION) (**1.0.0-rc1** для текущего MVP); инсталлятор подставляет его при загрузке релизных артефактов.

## Development (Windows) vs deployment (Linux)

Typical workflow for this project:

| Phase | Environment | Notes |
|-------|-------------|--------|
| **Development** | **Windows 11** (local PC, IDE) | Use **Git Bash** or **WSL** to run the same checks as CI (`make ci`, `bash scripts/check-linux-artifacts.sh`). Avoid CRLF in `scripts/**/*.sh`; keep paths Linux-oriented in configs and docs. |
| **CI / QA** | **GitHub Actions** (hosted Linux runner) | Same Go/lint/shell checks as on Alma; for **HAProxy/OS parity** also run **`make ci`** or integration tests on **AlmaLinux** (e.g. pilot **`waf-dev`**, see [DEV_HOST.md](DEV_HOST.md)). |
| **Production** | **AlmaLinux / RHEL-family** (`dnf`) or **Debian / Ubuntu** (`apt`) | Same `scripts/install.sh` layout: `/var/lib/easy-waf`, `/etc/easy-waf`, systemd. Package installs follow the detected package manager. |

The **source of truth** for “will it ship?” is what passes on **Linux**, not only ad-hoc commands in PowerShell without `bash`/`go`.

Pilot SSH host alias **`waf-dev`** (dev/test): see **[DEV_HOST.md](DEV_HOST.md)** and workspace **`.vscode/settings.json`**.

## What the installer does

[`scripts/install.sh`](../scripts/install.sh) (run as **root**):

1. Creates user `easy-waf` and directory layout under `EASY_WAF_STATE_DIR` (default `/var/lib/easy-waf`): `haproxy/`, `revisions/`, `certs/`, `acme/webroot`, `secrets/` (0700).
2. Installs **`easy-waf-api`**, **`easy-waf-acmed`**, optionally **`easy-wafd`** from `dist/` (or `EASY_WAF_DIST_DIR`).
3. Copies [`configs/defaults/easy-waf.env.example`](../configs/defaults/easy-waf.env.example) to `/etc/easy-waf/easy-waf.env` if missing.
4. Copies **systemd** units from `packaging/systemd/` to `/etc/systemd/system/` and runs `daemon-reload` (unless `EASY_WAF_SKIP_SYSTEMD=1`).
5. Optionally (`EASY_WAF_INSTALL_OS_PACKAGES=1`) installs base packages via **dnf** (Alma/RHEL) or **apt** (Debian/Ubuntu): HAProxy, firewalld, fail2ban, nginx, CA certs. **PostgreSQL server defaults on** (`EASY_WAF_INSTALL_POSTGRES` defaults to **1**); set **`EASY_WAF_INSTALL_POSTGRES=0`** when using an external database only.
6. After `/etc/easy-waf/easy-waf.env` exists, when local PostgreSQL was installed: **prepends** [`scripts/lib/pg-hba-easywaf.sh`](../scripts/lib/pg-hba-easywaf.sh) rules so TCP `127.0.0.1` uses **scram-sha-256** for `easywaf` (avoids Alma/RHEL defaults that often use **ident** and break `DATABASE_URL` password auth), **creates** role and database `easywaf`, and may **rotate** weak default passwords (see [`scripts/lib/db-password.sh`](../scripts/lib/db-password.sh)).
7. Optionally **`EASY_WAF_ENABLE_SYSTEMD_UNITS=0`** skips `systemctl enable --now` at the end (default is to **start** services).
8. Optionally **`EASY_WAF_INSTALL_CROWDSEC=1`**: after `/etc/easy-waf/easy-waf.env` exists, installs CrowdSec from packagecloud, SPOA bouncer, registers bouncers, writes **`CROWDSEC_LAPI_*`** (see [CROWDSEC.md](CROWDSEC.md)).
9. Runs **restorecon** on state/config paths when SELinux tools are present (typically Alma/RHEL only).

Optional **CrowdSec** + **HAProxy SPOA** packages: set **`EASY_WAF_INSTALL_CROWDSEC=1`** on **`scripts/install.sh`** (non-interactive), or use **`scripts/install-interactive.sh`** (see [CROWDSEC.md](CROWDSEC.md)).

## AlmaLinux (bare metal / VM)

1. Clone the repo on the target host (or unpack a source tree). Run **`sudo bash scripts/install.sh`** — by default it **installs OS packages** (`EASY_WAF_INSTALL_OS_PACKAGES` defaults to **1**), **acquires binaries** by trying a **GitHub release** matching [`VERSION`](../VERSION) / `EASY_WAF_RELEASE_VERSION`, otherwise installs **Go + make + git** via **dnf** or **apt** (on older Debian, Go **1.22+** may be bootstrapped from **go.dev**), then **`make build`**. Minimal footprint: `EASY_WAF_INSTALL_OS_PACKAGES=0`. Pre-built only: `EASY_WAF_SKIP_BINARY_FETCH=1 EASY_WAF_DIST_DIR=/path/to/dist`. Published releases: [`scripts/download-release.sh`](../scripts/download-release.sh).
2. **Recommended (interactive, LAN-only API + optional CrowdSec):** `sudo bash scripts/install-interactive.sh`  
   **Or minimal:** `sudo bash scripts/install.sh` (same as [QUICKSTART.md](QUICKSTART.md): local PostgreSQL + DB provisioning + start services by default).
3. **External database only:** `sudo EASY_WAF_INSTALL_POSTGRES=0 bash scripts/install.sh`, edit `/etc/easy-waf/easy-waf.env` (`DATABASE_URL`), then `sudo systemctl enable --now easy-waf-api easy-waf-acmed` (or use `EASY_WAF_ENABLE_SYSTEMD_UNITS=0` on install and start after editing).
4. If you did not enable CrowdSec during install: use **`EASY_WAF_INSTALL_CROWDSEC=1`** with `install.sh`, run **`install-interactive.sh`**, or install **CrowdSec** + HAProxy **SPOE bouncer** manually per [CROWDSEC.md](CROWDSEC.md).

## Debian / Ubuntu (bare metal / VM)

Same installer as on Alma: **`sudo bash scripts/install.sh`**. Requirements:

- **root** (or `sudo`)
- **`apt-get`** available (Debian, Ubuntu, and derivatives)
- **systemd** (default on supported releases)

Differences from Alma/RHEL:

- Packages are installed with **`apt-get install`** (see [`scripts/install.sh`](../scripts/install.sh) `apt` branch).
- **PostgreSQL** uses the Debian/Ubuntu layout (clusters under `/var/lib/postgresql/`); provisioning still uses `sudo -u postgres` and the same **`pg_hba`** helper for password auth on `127.0.0.1`.
- **SELinux** `restorecon` is skipped when not installed.
- **CrowdSec** (optional, via `install-interactive.sh`) uses the official **DEB** packagecloud install script.

CI also runs a **Ubuntu 24.04** container job (`.github/workflows/ci.yml`, `deb-family-ci`) alongside **AlmaLinux 10** so tests pass on both families.

## PostgreSQL password on first install

If **local PostgreSQL** is installed and `DATABASE_URL` still uses the example passwords **`easywaf:secret`** or **`easywaf:easywaf`**, **`scripts/lib/db-password.sh`** runs **`ALTER USER easywaf`** and rewrites **`DATABASE_URL`** with a random hex password (unless `EASY_WAF_ROTATE_WEAK_DB_PASSWORD=0`). Always use a strong password for external databases.

If you see **`Ident authentication failed for user "easywaf"`**, run **`sudo bash scripts/lib/pg-hba-easywaf.sh`** (or re-run **`install.sh`**) — see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## OVF / OVA (appliance image)

**Recommended bake into the template:**

| Layer | Suggestion |
|-------|------------|
| OS | AlmaLinux 10 minimal + updates |
| Packages | `haproxy`, `nginx`, `firewalld`, `fail2ban`, `postgresql-server` *or* leave DB external |
| Binaries | Pre-place `easy-waf-api`, `easy-waf-acmed` in `/usr/sbin/` from CI build |
| systemd | Pre-enable `firewalld`, `fail2ban`; **do not** auto-enable `easy-waf-*` until first-boot config |
| First boot | cloud-init or `rc.local` replacement: write `/etc/easy-waf/easy-waf.env` from metadata, `systemctl enable --now easy-waf-api easy-waf-acmed` |
| Secrets | **Never** bake real `DATABASE_URL` or `EASY_WAF_ADMIN_TOKEN` into the image — inject at deploy time |
| Disk | Separate `/var/lib/easy-waf` for certs and generated configs (snapshot-friendly) |

**VM sizing (ESXi / QEMU–KVM):** see **[VM-REQUIREMENTS.md](VM-REQUIREMENTS.md)** — vCPU, RAM, disk, and NIC/controller choices.

See [packaging/ovf/README.md](../packaging/ovf/README.md) for a minimal checklist.

## Release artifacts (for `download-release.sh`)

Publish a tarball layout:

```
easy-waf_<version>_linux_amd64.tar.gz
  easy-waf-api
  easy-waf-acmed
  easy-wafd
  easy-waf-admin
  packaging/systemd/*.service
  configs/defaults/easy-waf.env.example
```

CI should run `make build` and pack the above so `scripts/install.sh` can run from extracted tree.

## Upgrades

Use [`scripts/upgrade.sh`](../scripts/upgrade.sh) with a directory or `.tar.gz` containing new binaries; it reuses `install.sh` and restarts units.
