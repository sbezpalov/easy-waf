# CrowdSec Integration

## Components

1. **CrowdSec Agent** parses logs (e.g. HAProxy) — configure acquisition under `/etc/crowdsec/`.
2. **Local API (LAPI)** on `http://127.0.0.1:8080` by default.
3. **HAProxy SPOA bouncer** (`crowdsec-haproxy-spoa-bouncer`) connects to LAPI and talks to HAProxy via SPOE.

## Automated install (recommended)

On **AlmaLinux / RHEL** (`dnf`) or **Debian / Ubuntu** (`apt`), run as **root**:

```bash
sudo bash scripts/install-interactive.sh
```

### Non-interactive install (`install.sh`)

Easy WAF treats CrowdSec as part of the **appliance**: on **dnf** / **apt**, **`scripts/install.sh`** installs **`crowdsec`** and **`crowdsec-haproxy-spoa-bouncer`** by default so **`crowdsec.service`** and **`crowdsec-haproxy-spoa-bouncer.service`** exist on the host. After a **first-time** agent install, both units are left **stopped** and **`systemctl disable`**, so nothing listens on LAPI until you choose to start it (air-gapped / staged rollouts).

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_INSTALL_CROWDSEC` | `1` | Set to **`0`** to skip CrowdSec/SPOA packages entirely (e.g. air-gapped hosts). |
| `EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL` | `0` | Set to **`1`** in the same `install.sh` run to **start** `crowdsec`, wait for LAPI, register bouncers **`easy-waf-spoa`** / **`easy-waf-api`**, inject the SPOA key, **`enable --now`** the SPOA bouncer, and write **`CROWDSEC_LAPI_*`** into **`/etc/easy-waf/easy-waf.env`**. |
| `EASY_WAF_CROWDSEC_CONSOLE_TOKEN` | *(empty)* | If set, runs `cscli console enroll <token>` during the bootstrap step (when `AUTO_START_AFTER_INSTALL=1`). |
| `EASY_WAF_FAIL2BAN_AUTO_START` | `0` | Set to **`1`** to **`systemctl start fail2ban`** immediately after package install (otherwise only **`enable`** at boot, like CrowdSec’s staged model). |

**Phase 1 — packages (default every run when `INSTALL_CROWDSEC=1`):** add CrowdSec **packagecloud** repo, `dnf`/`apt` install **`crowdsec`** + **`crowdsec-haproxy-spoa-bouncer`**. On the **first** install of the `crowdsec` package, run **`systemctl stop` + `disable`** for both units so the host stays quiet until you bootstrap.

**Phase 2 — LAPI bootstrap (only when `EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`):** `systemctl enable --now crowdsec` → wait for LAPI → optional **`cscli console enroll`** → recreate bouncers → inject SPOA YAML → **`enable --now crowdsec-haproxy-spoa-bouncer`** → **`CROWDSEC_LAPI_URL`** / **`CROWDSEC_LAPI_KEY`** in **`easy-waf.env`**.

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

## Verification

- UI: **CrowdSec** section — **Ping LAPI** / **Load decisions** when the bouncer key is configured.
- CLI: `cscli metrics`, `systemctl status crowdsec crowdsec-haproxy-spoa-bouncer`

## HAProxy logs and acquisition (align with easy-waf)

Easy WAF generates **`log stdout format raw local0`** in the global section. Under **systemd**, these lines usually show up in the journal (e.g. `journalctl -u haproxy -f`), not in `/var/log/haproxy.log`.

CrowdSec’s stock **file** acquisition examples often assume a path such as `/var/log/haproxy.log`. To use hub parsers (e.g. `crowdsecurity/haproxy`) with a **file** source, pick one approach:

1. **rsyslog (or similar)** — forward `local0` / program `haproxy` to a dedicated file, e.g. `/var/log/haproxy/easy-waf-edge.log`, and point acquisition at that file with `labels: { type: haproxy }` (same idea as a manual `acquis.d/*.yaml`).
2. **Journal acquisition** — if your CrowdSec build supports ingesting the systemd journal for the HAProxy unit, use that instead of a flat file (paths vary by distribution; check upstream docs for your version).
3. Avoid editing the generated `haproxy.cfg` by hand on the appliance; change the template in the repo if you later add an **optional** second `log` line behind a setting.

Keep **`filter spoe engine <name> config <path>`** in the generated config aligned with the **`[spoe-agent]` / bouncer** section names in `/etc/haproxy/crowdsec.cfg` (or the path in **Settings** → `spoe_config_path` / `crowdsec_engine_name`). A mismatch prevents decisions from reaching the edge.

See also [OPERATIONS.md](OPERATIONS.md) for paths and validation.
