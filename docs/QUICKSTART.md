# Quick Start

**Target:** Ubuntu 24.04 LTS (server), **root** on the appliance.

**Версия поставки:** см. корневой [`VERSION`](../VERSION) в репозитории (**1.0.0**); `scripts/install.sh` использует его для попытки скачать готовые бинарники с GitHub Releases (см. [`.github/workflows/release.yml`](../.github/workflows/release.yml)).

## One-command install

From the repo root on the VM:

```bash
sudo bash scripts/install.sh
```

This **by default** (full appliance — no extra flags):

1. Installs **HAProxy, nftables, nginx**, **PostgreSQL**, **fail2ban** (starts if installed), and **CrowdSec + HAProxy SPOA bouncer** (LAPI bootstrap, bouncer keys in `easy-waf.env`).
2. Creates `/etc/easy-waf/easy-waf.env` with **`0.0.0.0:8000` / `0.0.0.0:8443`**; if an old env binds a stale LAN IP, install rewrites it to `0.0.0.0`.
3. Builds or downloads **easy-waf** binaries, installs systemd units, and **starts** `easy-waf-api`, `easy-waf-acmed`, **crowdsec**, and **crowdsec-haproxy-spoa-bouncer** when packages install successfully.

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

- **UI (LAN):** по умолчанию **`EASY_WAF_LISTEN_HTTP=0.0.0.0:8000`** и **`EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443`**. Открой **`http://<LAN-IP>:8000`** или **`https://<LAN-IP>:8443`**. На **8443** изначально **самоподписанный** сертификат (`…/secrets/management.crt`); замена — блок **Management TLS** в UI или `PUT /api/v1/settings/management-tls`. **`install.sh`** настраивает **nftables**: **8000 и 8443/tcp** только с **127.0.0.0/8** и **RFC1918** (когда **`EASY_WAF_NFT_MGMT_LAN=1`**).
- **Login:** `admin` / `admin`, then change password when prompted.

**Старый формат `EASY_WAF_LISTEN=...`:** задай в `/etc/easy-waf/easy-waf.env` переменные **`EASY_WAF_LISTEN_HTTP`** / **`EASY_WAF_LISTEN_HTTPS`**, удали строку **`EASY_WAF_LISTEN`**, обнови unit из `packaging/systemd/`, затем:

`sudo bash scripts/fix-nftables-edge.sh`

и `sudo systemctl daemon-reload && sudo systemctl restart easy-waf-api`.

**Только loopback:** `EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`, `EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`, **`EASY_WAF_NFT_MGMT_LAN=0`** при установке.

**Без HTTPS:** `EASY_WAF_MANAGEMENT_HTTPS=0` — остаётся только HTTP (например на 8000).

## Interactive (LAN API, optional CrowdSec)

```bash
sudo bash scripts/install-interactive.sh
```

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
