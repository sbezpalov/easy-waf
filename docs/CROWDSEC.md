# CrowdSec Integration

## Components

1. **CrowdSec Agent** parses logs (e.g. HAProxy) — configure acquisition under `/etc/crowdsec/`.
2. **Local API (LAPI)** on `http://127.0.0.1:8080` by default.
3. **HAProxy SPOA bouncer** (`crowdsec-haproxy-spoa-bouncer`) connects to LAPI and talks to HAProxy via SPOE.

## Automated install (recommended)

On AlmaLinux / RHEL-family (with `dnf`), run as **root**:

```bash
sudo bash scripts/install-interactive.sh
```

The wizard can:

- Set **`EASY_WAF_LISTEN_HTTP` / `EASY_WAF_LISTEN_HTTPS`** (loopback or `0.0.0.0`), and optionally add **firewalld rich rules** so management **8000** and **8443/tcp** are allowed only from **RFC1918** (not from the public Internet).
- Install **CrowdSec** from the official [packagecloud repository](https://docs.crowdsec.net/u/getting_started/installation/linux/), then **`crowdsec-haproxy-spoa-bouncer`**.
- Optionally run **`cscli console enroll`** when you paste a **CrowdSec Console** enrollment token.
- Register two LAPI bouncers: one for the SPOA binary, one for **Easy WAF** UI health (`CROWDSEC_LAPI_KEY` in `/etc/easy-waf/easy-waf.env`).

Re-running the CrowdSec steps on the same host may fail if bouncer names already exist — remove them with `cscli bouncers delete <name>` first.

Non-interactive hints (see `scripts/install-interactive.sh` for the full list):

- `EASY_WAF_MGMT_MODE=loopback` or `lan_rfc1918`
- `EASY_WAF_INSTALL_CROWDSEC=1`
- `EASY_WAF_CROWDSEC_CONSOLE_TOKEN=...` (optional)

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
