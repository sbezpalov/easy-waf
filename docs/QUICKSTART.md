# Quick Start

[English](QUICKSTART.md) | [Русский](QUICKSTART.ru.md)

**Target:** Ubuntu 24.04 LTS (server), **root** on the appliance.

**Ship version:** see root [`VERSION`](../VERSION) in the repo (**1.4.1**); `scripts/install.sh` uses it to fetch the matching artifacts from GitHub Releases (see [`.github/workflows/release.yml`](../.github/workflows/release.yml)). Every artifact is verified against **`SHA256SUMS`** from the same release before anything is installed — see [SECURITY.md](SECURITY.md#supply-chain) and [ADR 0001](adr/0001-packaging-and-installer.md).

## One-command install

From the repo root on the VM:

```bash
sudo bash scripts/install.sh
```

This **by default** (full appliance — no extra flags):

1. Installs **HAProxy, nftables**, **PostgreSQL**, **fail2ban** (starts if installed), and **CrowdSec + HAProxy SPOA bouncer** (LAPI bootstrap, bouncer keys in `easy-waf.env`).
2. Installs the **`easy-waf` Debian package** for the version in `VERSION` — binaries in `/usr/sbin`, systemd units in `/lib/systemd/system`, `/etc/easy-waf/easy-waf.env` as a **dpkg conffile** so later upgrades keep your edits.
3. Sets the env file to **HTTPS `0.0.0.0:8443`** with **management HTTP off**; if an old env binds a stale LAN IP, install rewrites it to `0.0.0.0` (HTTP still requires loopback or `EASY_WAF_ALLOW_INSECURE_HTTP=1`).
4. **Starts** `easy-waf-hostd`, `easy-waf-api`, `easy-waf-acmed`, **crowdsec**, and **crowdsec-spoa-bouncer** when packages install successfully.

### Package only, without the provisioning

If PostgreSQL, nftables and CrowdSec are already how you want them, install the
package on its own and take over from there:

```bash
curl -fLO https://github.com/sbezpalov/easy-waf/releases/download/v1.4.1/easy-waf_1.4.1_amd64.deb
curl -fLO https://github.com/sbezpalov/easy-waf/releases/download/v1.4.1/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS        # do not skip this
sudo apt install ./easy-waf_1.4.1_amd64.deb
```

The package installs enabled but **not started**: set `DATABASE_URL` in
`/etc/easy-waf/easy-waf.env`, then `sudo systemctl start easy-waf-hostd
easy-waf-api easy-waf-acmed`.

### No network to GitHub

If neither the package nor the tarball can be downloaded and verified, the
installer **stops** rather than compiling on the appliance — a build would leave
Go, make and git installed on a machine that terminates TLS. Either point it at
artifacts you already have (`sudo EASY_WAF_DIST_DIR=/path/to/dist bash
scripts/install.sh`) or opt in explicitly with
`sudo EASY_WAF_BUILD_FROM_SOURCE=1 bash scripts/install.sh`.

**External PostgreSQL only** (no local `postgresql` package):

```bash
sudo EASY_WAF_INSTALL_POSTGRES=0 bash scripts/install.sh
```

Then set `DATABASE_URL` in `/etc/easy-waf/easy-waf.env` before starting services (or edit and `systemctl restart easy-waf-api easy-waf-acmed`).

**Do not auto-start** services after install (only install files):

```bash
sudo EASY_WAF_ENABLE_SYSTEMD_UNITS=0 bash scripts/install.sh
```

**CrowdSec** is **on by default** (`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`). See [CROWDSEC.md](CROWDSEC.md).

Staged / air-gapped (packages only, LAPI later):

```bash
sudo EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0 bash scripts/install.sh
sudo bash scripts/crowdsec-bootstrap-lapi.sh   # when online
```

Skip CrowdSec entirely: `sudo EASY_WAF_INSTALL_CROWDSEC=0 bash scripts/install.sh`

Optional **CrowdSec Console** enroll: `EASY_WAF_CROWDSEC_CONSOLE_TOKEN=...` during a run with **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`**.

## After install

- **UI (LAN):** by default **management HTTP is off** and **`EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443`**. Open **`https://<LAN-IP>:8443`**. Loopback HTTP: **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`**. Legacy cleartext LAN HTTP requires **`EASY_WAF_ALLOW_INSECURE_HTTP=1`** (discouraged). Port **8443** starts with a **self-signed** certificate (`…/secrets/management.crt`); replace via the **Management TLS** block in the UI or `PUT /api/v1/settings/management-tls`. **`install.sh`** configures **nftables**: **8000 and 8443/tcp** only from **127.0.0.0/8** and **RFC1918** (when **`EASY_WAF_NFT_MGMT_LAN=1`**). **`/health`** is on the HTTPS listener (and on HTTP only if you enabled it). ACME HTTP-01 stays on loopback **`127.0.0.1:8089`**.
- **Login:** there is no default password. As root on the appliance run **`easy-waf-admin print-enrollment`**, then enroll in the UI (or `POST /api/v1/auth/enroll`) with that one-time secret.

**Legacy `EASY_WAF_LISTEN=...` format:** set **`EASY_WAF_LISTEN_HTTP`** / **`EASY_WAF_LISTEN_HTTPS`** in `/etc/easy-waf/easy-waf.env` and remove the **`EASY_WAF_LISTEN`** line. Do **not** copy units from `packaging/systemd/` into `/etc/systemd/system/` — those shadow the packaged units in `/lib/systemd/system/` and make the next upgrade look applied while systemd keeps starting the old definition. Then:

`sudo bash scripts/fix-nftables-edge.sh`

and `sudo systemctl daemon-reload && sudo systemctl restart easy-waf-api`.

**HTTPS-only loopback (interactive default):** `EASY_WAF_LISTEN_HTTP=off`, `EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`, **`EASY_WAF_NFT_MGMT_LAN=0`**. Use an SSH port-forward when administering remotely.

**Legacy loopback HTTP + HTTPS:** `EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`, `EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`, **`EASY_WAF_NFT_MGMT_LAN=0`**.

**No HTTPS:** `EASY_WAF_MANAGEMENT_HTTPS=0` plus **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`** (or non-loopback with **`EASY_WAF_ALLOW_INSECURE_HTTP=1`**). The process will not start if both listeners are off.

## Interactive installer

```bash
sudo bash scripts/install-interactive.sh
```

The default mode is **`https_loopback`** (HTTPS-only on `127.0.0.1:8443`). Select **`lan_rfc1918`** for HTTPS on `0.0.0.0:8443` with the management nftables policy, or explicit legacy **`loopback`** only when cleartext loopback HTTP is still required. Non-interactive override: `EASY_WAF_MGMT_MODE=https_loopback|lan_rfc1918|loopback`.

## First application

1. Log in to the UI.
2. **Applications → Add** → profile (e.g. `home-assistant`).
3. Hostname, backend IP:port, WebSocket if needed.
4. **Certificates** → issue (staging first).
5. **Apply** → validates `haproxy -c` and reloads HAProxy.

## Paths

| Item | Default |
|------|---------|
| State | `/var/lib/easy-waf` |
| HAProxy config | `/var/lib/easy-waf/haproxy/haproxy.cfg` |
| Env | `/etc/easy-waf/easy-waf.env` |
| Host firewall | `/etc/nftables/easy-waf.nft` |

More detail: [DEPLOYMENT.md](DEPLOYMENT.md), [OPERATIONS.md](OPERATIONS.md) (manual `haproxy -c`, revisions, `EASY_WAF_SKIP_*`), [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

**Backup / restore:** [BACKUP_RESTORE.md](BACKUP_RESTORE.md) — `sudo bash scripts/backup.sh` (single `.tar.gz` with DB dump + state + `/etc/easy-waf`), `sudo bash scripts/restore.sh …`.
