# CrowdSec Integration

## Components

1. **CrowdSec Agent** parses logs (e.g. HAProxy) — configure acquisition under `/etc/crowdsec/`.
2. **Local API (LAPI)** on `http://127.0.0.1:8080` by default.
3. **HAProxy SPOA bouncer** (apt package **`crowdsec-haproxy-spoa-bouncer`**, systemd unit **`crowdsec-spoa-bouncer.service`** on Ubuntu 24.04) connects to LAPI and talks to HAProxy via SPOE.

## Automated install (recommended)

On **Ubuntu 24.04+** (`apt`), run as **root**:

```bash
sudo bash scripts/install-interactive.sh
```

### Non-interactive install (`install.sh`)

Easy WAF treats CrowdSec as part of the **appliance**: on **apt**, **`scripts/install.sh`** installs **`crowdsec`** and **`crowdsec-haproxy-spoa-bouncer`** by default. The Debian **`crowdsec`** postinst starts **`crowdsec.service`** once; on a fresh VM the local API can briefly return errors while SQLite and hub data settle. The installer **waits for LAPI** (any HTTP response on `127.0.0.1:8080`, not only `curl -f` success) and, on **first** agent install only, runs **`apt-get -f install` / `dpkg --configure` once** plus controlled restarts. **Re-runs** when `crowdsec` is already installed use **systemd-only** recovery (no repeated `apt-get` spam).

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_INSTALL_CROWDSEC` | `1` | Set to **`0`** to skip CrowdSec/SPOA packages entirely. |
| `EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL` | **`1`** | Set to **`0`** for staged install (packages only, units stopped until `scripts/crowdsec-bootstrap-lapi.sh`). When **`1`**, `install.sh` **starts** `crowdsec`, registers bouncers **`easy-waf-spoa`** / **`easy-waf-api`**, injects the SPOA key, **`enable --now`** the SPOA bouncer, and writes **`CROWDSEC_LAPI_*`** into **`/etc/easy-waf/easy-waf.env`**. |
| `EASY_WAF_CROWDSEC_CONSOLE_TOKEN` | *(empty)* | If set, runs `cscli console enroll <token>` during the bootstrap step (when `AUTO_START_AFTER_INSTALL=1`). |
| `EASY_WAF_FAIL2BAN_AUTO_START` | **`1`** | Set to **`0`** to only **`enable`** fail2ban at boot without immediate **`start`**. |

**Phase 1 — packages (default every run when `INSTALL_CROWDSEC=1`):** add CrowdSec **packagecloud** repo, `apt` install **`crowdsec`** + **`crowdsec-haproxy-spoa-bouncer`**, then ensure the agent is **healthy** (LAPI on `127.0.0.1:8080`) before continuing.

**Phase 2 — LAPI bootstrap (only when `EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`):** `systemctl enable --now crowdsec` (with retries if needed) → wait for LAPI → optional **`cscli console enroll`** → recreate bouncers → inject SPOA YAML → **`enable --now crowdsec-spoa-bouncer`** (or legacy **`crowdsec-haproxy-spoa-bouncer`** on some distros) → **`CROWDSEC_LAPI_URL`** / **`CROWDSEC_LAPI_KEY`** in **`easy-waf.env`**.

When **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0`**, packages are installed but **`crowdsec_leave_stopped_disabled`** leaves units stopped until **`scripts/crowdsec-bootstrap-lapi.sh`**.

**Errors (non-fatal where noted):** repo or package failures log **WARNING** and continue. If LAPI is not ready during bootstrap, bouncer registration is skipped; fix **`systemctl status crowdsec`** and re-run bootstrap.

Examples:

```bash
sudo bash scripts/install.sh
```

```bash
sudo EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1 EASY_WAF_CROWDSEC_CONSOLE_TOKEN='your-console-enroll-token' bash scripts/install.sh
```

**Later / second machine:** after packages are present, start LAPI and register keys without re-reading prompts:

```bash
sudo bash scripts/crowdsec-bootstrap-lapi.sh
```

`install-interactive.sh` asks **Start CrowdSec LAPI now… (y/n)**; answering **y** sets **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`** for the embedded `install.sh` run (same bouncer names **`easy-waf-spoa`** / **`easy-waf-api`** as non-interactive).

Re-running **`install.sh`** with **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`** on a host that already had the agent installed is safe (bouncers are deleted and recreated). For manual `cscli bouncers add`, remove duplicates with `cscli bouncers delete <name>` first.

Non-interactive hints for **`install-interactive.sh`**: see `scripts/install-interactive.sh` header — e.g. `EASY_WAF_MGMT_MODE=loopback` or `lan_rfc1918`, `EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`, `EASY_WAF_CROWDSEC_CONSOLE_TOKEN=...`.

## SPOE paths and naming

Vendor SPOE configuration is installed as **`/etc/haproxy/crowdsec.cfg`** when `/etc/haproxy` exists before package install. The generated HAProxy config uses:

```text
filter spoe engine crowdsec config /etc/haproxy/crowdsec.cfg
```

The engine id **`crowdsec`** must match the **`[crowdsec]`** section in that file (see [HAProxy SPOA bouncer](https://docs.crowdsec.net/u/bouncers/haproxy_spoa.md)). Full examples ship under `/usr/share/doc/crowdsec-haproxy-spoa-bouncer/examples/`.

For advanced behaviour (CAPTCHA, ban pages, AppSec), follow upstream docs: additional `global` **lua-load** lines and `http-request send-spoe-group` may be required beyond the minimal `filter spoe` line embedded in easy-waf’s template.

## Variables

- **`CROWDSEC_LAPI_URL`** / **`CROWDSEC_LAPI_KEY`** in `/etc/easy-waf/easy-waf.env` — used by **easy-waf-api** to reach LAPI (management bouncer key).

## Management API (UI)

Authenticated session:

- `GET /api/v1/integrations/crowdsec` — LAPI reachability (ping).
- `GET /api/v1/integrations/crowdsec/decisions` — JSON from LAPI `GET /v1/decisions?limit=100` (blocked IPs preview; aligns with [prompts.md](../prompts.md) §7.5).
- `DELETE /api/v1/integrations/crowdsec/decisions/{id}` — removes one decision via LAPI `DELETE /v1/decisions/{id}` (same ID as in the decisions list). Audit: `crowdsec.decision_deleted`.
- `POST /api/v1/integrations/crowdsec/decisions` — adds a manual ban or **whitelist**; body JSON `{ "ip", "type": "ban"|"whitelist", "duration": "1h"|"4h"|"24h"|"168h"|"permanent", "reason" }`. Proxied to LAPI `POST /v1/decisions` as a single-element array (`scope: Ip`, `origin: easy-waf`, `scenario` = `reason`). Whitelist uses a long LAPI duration (`876000h`). Audit: `crowdsec.decision_added`.

### Managing decisions from UI

Open **CrowdSec** in the management UI (after **Settings → Load from server** so LAPI URL and key are present):

1. **Active decisions** — table is filled from `GET …/decisions` (up to 100 rows). Each row has **Unban**; you are prompted to confirm (IP and decision ID are shown in the dialog). Success calls the delete API and refreshes the table.
2. **Allow IP (whitelist)** — enter **IP** and optional **Reason**, then **Allow IP** (`type: whitelist`, long duration).
3. **Manual ban** — enter **IP**, pick **Duration** (1h / 4h / 24h / 7 days / permanent), optional **Reason**, then **Ban IP**. Permanent bans use a very long LAPI duration (`876000h`). The table refreshes after a successful ban. Whitelist rows show **Remove** instead of **Unban**.

Requirements: **`CROWDSEC_LAPI_URL`** and a valid **`CROWDSEC_LAPI_KEY`** (machine bouncer with decisions rights, e.g. from `cscli bouncers add -o raw`) in **`/etc/easy-waf/easy-waf.env`**. If LAPI returns an error, the UI shows the API error text.

The generic HTTP audit middleware also records mutating calls under category **crowdsec**; filter audit logs with action substring **`crowdsec`** to see both those rows and the explicit `crowdsec.decision_*` entries.

## Verification

- UI: **CrowdSec** section — **Ping LAPI** / **Load decisions** when the bouncer key is configured.
- CLI: `cscli metrics`, `systemctl status crowdsec crowdsec-spoa-bouncer.service` (unit name on Ubuntu 24.04; apt package is still `crowdsec-haproxy-spoa-bouncer`)

**Out of the box:** `sudo bash scripts/install.sh` (default `EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`) installs both packages, registers bouncers `easy-waf-api` / `easy-waf-spoa`, writes `CROWDSEC_LAPI_*` to `/etc/easy-waf/easy-waf.env`, syncs settings into PostgreSQL, enables `crowdsec-spoa-bouncer.service`, and verifies `GET /v1/decisions`. No manual `cscli` or UI **Load from server** is required for CrowdSec decisions.

## HAProxy logs and acquisition (align with easy-waf)

Easy WAF generates **`log stdout format raw local0`** in the global section. Under **systemd**, these lines usually show up in the journal (e.g. `journalctl -u haproxy -f`), not in `/var/log/haproxy.log`.

CrowdSec’s stock **file** acquisition examples often assume a path such as `/var/log/haproxy.log`. To use hub parsers (e.g. `crowdsecurity/haproxy`) with a **file** source, pick one approach:

1. **rsyslog (or similar)** — forward `local0` / program `haproxy` to a dedicated file, e.g. `/var/log/haproxy/easy-waf-edge.log`, and point acquisition at that file with `labels: { type: haproxy }` (same idea as a manual `acquis.d/*.yaml`).
2. **Journal acquisition** — if your CrowdSec build supports ingesting the systemd journal for the HAProxy unit, use that instead of a flat file (paths vary by distribution; check upstream docs for your version).
3. Avoid editing the generated `haproxy.cfg` by hand on the appliance; change the template in the repo if you later add an **optional** second `log` line behind a setting.

Keep **`filter spoe engine <name> config <path>`** in the generated config aligned with the **`[spoe-agent]` / bouncer** section names in `/etc/haproxy/crowdsec.cfg` (or the path in **Settings** → `spoe_config_path` / `crowdsec_engine_name`). A mismatch prevents decisions from reaching the edge.

See also [OPERATIONS.md](OPERATIONS.md) for paths and validation.
