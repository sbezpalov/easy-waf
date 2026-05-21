# ACME / Let's Encrypt

## Modes

- **Staging**: Let's Encrypt staging URL; avoids rate limits during testing.
- **Production**: default LE production.

## HTTP-01

Requires HAProxy on port **80** with a frontend rule for `/.well-known/acme-challenge/`. **Lego** writes token files under **`${ACMEWebrootPath}/.well-known/acme-challenge/`** (default `${EASY_WAF_STATE_DIR}/acme/webroot/...`).

The generated HAProxy config routes those URLs to **`bk_acme` → `127.0.0.1:8089`**. **`easy-waf-api`** listens on that loopback address by default and serves files from the webroot so HAProxy health checks succeed. Override or disable with **`EASY_WAF_ACME_INTERNAL_HTTP`** (see `configs/defaults/easy-waf.env.example`): unset = `127.0.0.1:8089`; `0` / `off` / `false` = disabled.

## DNS-01

Implemented via **Lego** (`easy-waf-acmed`): `dns_provider` is one of `cloudflare`, `cloudns` (default when empty), `route53`, `webhook` (Lego `httpreq`). Credentials live in a **root-only env file** referenced by `dns_credentials_env_file` — see [DNS01.md](DNS01.md) and `configs/examples/dns-*.env.example`.

### Split-DNS and propagation checks

After publishing the TXT record, Lego polls **recursive resolvers** until the challenge is visible publicly. If the appliance uses an **internal DNS forwarder** that does not expose the public TXT view, DNS-01 can hang or fail.

Set global **`acme_dns_resolvers`** to public resolvers, for example:

```json
{ "acme_dns_resolvers": ["1.1.1.1:53", "8.8.8.8:53"] }
```

Empty list = system resolver (`/etc/resolv.conf`). See [DNS.md](DNS.md).

## Renewal

- `easy-waf-acmed` runs a periodic loop (`EASY_WAF_ACME_TICK`, default 30s). It processes `acme_status = pending` and renews certs whose `not_after` is inside the renewal window.
- On success: PEM files under `/var/lib/easy-waf/certs/<id>/`, DB updated, then `engine.Apply` reloads HAProxy (unless `EASY_WAF_ACME_SKIP_APPLY=1`).
- Account private key is stored at `${EASY_WAF_STATE_DIR}/acme/account.pem` (Lego HTTP-01 webroot: `${ACMEWebrootPath}` / default `.../acme/webroot`).

## Multiple hostnames / one public IP

Each **certificate** is a separate row (DNS names in `primary_domain` / `san`). Each **application** sets `certificate_id` to the cert that covers its `public_host`. HAProxy uses a **single `crt-list`** on **:443** so **SNI** selects the right PEM while **Host** routes to the backend — see **TLS, SNI, and per-application certificates** in [ARCHITECTURE.md](ARCHITECTURE.md).

## HAProxy PEM layout

Full chain + private key concatenated or separate `crt` + `key` as required by your `crt` line; templates are documented in `configs/defaults`.
