# ACME / Let's Encrypt

## Modes

- **Staging**: Let's Encrypt staging URL; avoids rate limits during testing.
- **Production**: default LE production.

## HTTP-01

Requires HAProxy (or NGINX) to serve ACME challenges on port 80. The daemon writes challenge responses to the state directory and injects HAProxy frontend ACLs for `/.well-known/acme-challenge/`.

## DNS-01

Implemented via **Lego** (`easy-waf-acmed`): `dns_provider` is one of `cloudflare`, `cloudns` (default when empty), `route53`, `webhook` (Lego `httpreq`). Credentials live in a **root-only env file** referenced by `dns_credentials_env_file` — see [DNS01.md](DNS01.md) and `configs/examples/dns-*.env.example`.

## Renewal

- `easy-waf-acmed` runs a periodic loop (`EASY_WAF_ACME_TICK`, default 30s). It processes `acme_status = pending` and renews certs whose `not_after` is inside the renewal window.
- On success: PEM files under `/var/lib/easy-waf/certs/<id>/`, DB updated, then `engine.Apply` reloads HAProxy (unless `EASY_WAF_ACME_SKIP_APPLY=1`).
- Account private key is stored at `${EASY_WAF_STATE_DIR}/acme/account.pem` (Lego HTTP-01 webroot: `${ACMEWebrootPath}` / default `.../acme/webroot`).

## Multiple hostnames / one public IP

Each **certificate** is a separate row (DNS names in `primary_domain` / `san`). Each **application** sets `certificate_id` to the cert that covers its `public_host`. HAProxy uses a **single `crt-list`** on **:443** so **SNI** selects the right PEM while **Host** routes to the backend — see **TLS, SNI, and per-application certificates** in [ARCHITECTURE.md](ARCHITECTURE.md).

## HAProxy PEM layout

Full chain + private key concatenated or separate `crt` + `key` as required by your `crt` line; templates are documented in `configs/defaults`.
