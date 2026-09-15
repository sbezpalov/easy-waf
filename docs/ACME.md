# ACME / Let's Encrypt

## Modes

- **Staging**: Let's Encrypt staging URL; avoids rate limits during testing.
- **Production**: live Let's Encrypt.

**A fresh appliance issues from staging.** `acme_staging` defaults to **`true`** (`internal/config/types.go`), and the effective mode is `certificate.staging || settings.acme_staging` — the global flag **overrides** a per-certificate `staging: false`. Turn `acme_staging` off in global settings before you expect trusted certificates.

## HTTP-01

Requires HAProxy on port **80** with a frontend rule for `/.well-known/acme-challenge/`. **Lego** writes token files under **`${ACMEWebrootPath}/.well-known/acme-challenge/`** (default `${EASY_WAF_STATE_DIR}/acme/webroot/...`).

The generated HAProxy config routes those URLs to **`bk_acme` → `127.0.0.1:8089`**. **`easy-waf-api`** listens on that loopback address and serves files from the webroot so HAProxy health checks succeed.

`EASY_WAF_ACME_INTERNAL_HTTP` (see `configs/defaults/easy-waf.env.example`) has two usable values: **unset** = `127.0.0.1:8089`, and `0` / `off` / `false` = **disabled**. Do **not** point it at another address: the rendered backend line is a literal `server acme 127.0.0.1:8089 check` (`internal/haproxy/render.go`), so moving the listener leaves HAProxy checking a dead port and HTTP-01 fails with no obvious cause.

## DNS-01

Implemented via **Lego** (`easy-waf-acmed`): `dns_provider` is one of `cloudflare`, `cloudns` (default when empty), `route53`, `webhook` (Lego `httpreq`). Credentials live in an env file referenced by `dns_credentials_env_file` — see [DNS01.md](DNS01.md) and `configs/examples/dns-*.env.example`.

The file must be **readable by `easy-waf`**, not root-only: `easy-waf-acmed` runs as `User=easy-waf` (`packaging/systemd/easy-waf-acmed.service`) and opens the file itself. `chown root:easy-waf` + `chmod 0640` works; `0600 root:root` fails issuance with `dns env: … permission denied`.

### Split-DNS and propagation checks

After publishing the TXT record, Lego polls **recursive resolvers** until the challenge is visible publicly. If the appliance uses an **internal DNS forwarder** that does not expose the public TXT view, DNS-01 can hang or fail.

Set global **`acme_dns_resolvers`** to public resolvers, for example:

```json
{ "acme_dns_resolvers": ["1.1.1.1:53", "8.8.8.8:53"] }
```

Empty list = system resolver (`/etc/resolv.conf`). See [DNS.md](DNS.md).

## Renewal

- `easy-waf-acmed` runs a periodic loop (`EASY_WAF_ACME_TICK`, default 30s). It processes `acme_status = pending` and renews certs whose `not_after` falls inside the renewal window.
- **The renewal window is a hardcoded 30 days** (`cmd/easy-waf-acmed/main.go`). The `acme_renewal_interval` setting (default 12h) is **not read by acmed** — changing it has no effect today.
- **Nothing is issued until `acme_email` is set** in global settings. Without it the worker logs `acmed: ACMEEmail not set in global settings — idle` once per tick and does nothing else. This is the first thing to check when certificates stay `pending`.
- On success: PEM files under `/var/lib/easy-waf/certs/<id>/`, DB updated, then `engine.Apply` reloads HAProxy — skipped if `EASY_WAF_ACME_SKIP_APPLY` is set to **any non-empty value**. The check is `!= ""`, so `EASY_WAF_ACME_SKIP_APPLY=0` also skips the apply. Comment the line out rather than setting it to `0`.
- Account private key is stored at `${EASY_WAF_STATE_DIR}/acme/account.pem` (Lego HTTP-01 webroot: `${ACMEWebrootPath}` / default `.../acme/webroot`).

## Multiple hostnames / one public IP

Each **certificate** is a separate row (DNS names in `primary_domain` / `san`). Each **application** sets `certificate_id` to the cert that covers its `public_host`. HAProxy uses a **single `crt-list`** on **:443** so **SNI** selects the right PEM while **Host** routes to the backend — see **TLS, SNI, and per-application certificates** in [ARCHITECTURE.md](ARCHITECTURE.md).

## HAProxy PEM layout

One file per certificate, and the generated `crt-list` carries exactly that one path per line — there is no separate `crt` + `key` form. The engine resolves it on apply (`internal/engine`):

- `fullchain_path` **and** `pem_key_path` set and both non-empty → concatenated into `${EASY_WAF_STATE_DIR}/certs/<id>/bundle.pem` (`internal/pemutil`). This is the ACME path.
- otherwise, `pem_crt_path` if set → used as-is, on the assumption that it already contains chain and key.
- otherwise → the certificate is **skipped** when the `crt-list` is built (`internal/haproxy/render.go`), which is why an incomplete certificate silently disappears from `:443` instead of failing loudly.
