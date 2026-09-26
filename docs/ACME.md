# ACME / Let's Encrypt

## Modes

- **Staging**: Let's Encrypt staging URL; avoids rate limits during testing.
- **Production**: live Let's Encrypt.

**A fresh appliance issues from staging.** `acme_staging` defaults to **`true`** (`internal/config/types.go`), and the effective mode is `certificate.staging || settings.acme_staging` — the global flag **overrides** a per-certificate `staging: false`. Turn `acme_staging` off in global settings before you expect trusted certificates.

## HTTP-01

Requires HAProxy on port **80** with a frontend rule for `/.well-known/acme-challenge/`. **Lego** writes token files under **`${ACMEWebrootPath}/.well-known/acme-challenge/`** (default `${EASY_WAF_STATE_DIR}/acme/webroot/...`).

The generated HAProxy config routes those URLs to **`bk_acme` → `127.0.0.1:8089`**. **`easy-waf-api`** listens on that loopback address and serves files from the webroot so HAProxy health checks succeed.

**To move it, change the setting, not the environment.** The address is the global
setting **`acme_internal_http`** (default `127.0.0.1:8089`), and both sides read
it: `easy-waf-api` listens on it, and the renderer writes it into the `bk_acme`
backend. It must be `ip:port` — a hostname is refused, because a `server` line
naming a host would need a `resolvers` section the renderer only emits for
application backends.

```bash
curl -X PATCH https://127.0.0.1:8443/api/v1/settings \
  -H "Content-Type: application/json" -H "X-Requested-With: XMLHttpRequest" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"acme_internal_http":"127.0.0.1:9090"}'
```

`EASY_WAF_ACME_INTERNAL_HTTP` (see `configs/defaults/easy-waf.env.example`) still
works for **switching the helper off** — `0` / `off` / `false` — and unset means
"use the setting". Using it to move the listener moves only the listener: the
rendered backend follows the setting, so the two disagree and HTTP-01 fails on a
backend nobody looks at. `easy-waf-api` logs a warning naming both addresses when
it starts in that state.

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

- `easy-waf-acmed` runs a periodic loop (`EASY_WAF_ACME_TICK`, default 30s). Each tick it claims due rows with `FOR UPDATE SKIP LOCKED` (so two workers never issue the same certificate) and marks them `issuing`. A row is due when it is:
  - `pending` (new, or the operator pressed **Request issue** / **Retry now**);
  - `failed` and its `acme_next_attempt_at` has passed;
  - `ready`, ACME-managed and its `not_after` falls inside the renewal window;
  - `issuing` for more than an hour (a worker died mid-issuance).
- **Failures retry on their own** with exponential backoff: 10m, 20m, 40m, … capped at 24h (`internal/acme/retry.go`). `acme_attempts` counts consecutive failures; success or a manual request resets it. The certificate dashboard shows such rows as **failed** (red), with the error and the next retry time on hover — including a renewal that failed while the old certificate is still valid.
- On success the worker writes `privkey.pem` and `fullchain.pem` atomically while holding the HAProxy apply lock, then updates only the columns it owns (paths, validity, status). If the operator edited the row during issuance, the result is discarded and the row is issued again on the next tick.
- **The renewal window is a hardcoded 30 days** (`cmd/easy-waf-acmed/main.go`). The `acme_renewal_interval` setting (default 12h) is **not read by acmed** — changing it has no effect today.
- **Nothing is issued until `acme_email` is set** in global settings. Without it the worker logs `acmed: ACMEEmail not set in global settings — idle` once per tick and does nothing else. This is the first thing to check when certificates stay `pending`.
- On success: PEM files under `/var/lib/easy-waf/certs/<id>/`, DB updated, then `engine.Apply` reloads HAProxy — skipped when `EASY_WAF_ACME_SKIP_APPLY` is set to a true value (`1`, `true`, `yes`, `on`). `0`, `false` and `off` mean "do not skip"; an unparseable value is treated as off and logged.
- Account private key is stored at `${EASY_WAF_STATE_DIR}/acme/account.pem` (Lego HTTP-01 webroot: `${ACMEWebrootPath}` / default `.../acme/webroot`).

## Multiple hostnames / one public IP

Each **certificate** is a separate row (DNS names in `primary_domain` / `san`). Each **application** sets `certificate_id` to the cert that covers its `public_host`. HAProxy uses a **single `crt-list`** on **:443** so **SNI** selects the right PEM while **Host** routes to the backend — see **TLS, SNI, and per-application certificates** in [ARCHITECTURE.md](ARCHITECTURE.md).

## HAProxy PEM layout

One file per certificate, and the generated `crt-list` carries exactly that one path per line — there is no separate `crt` + `key` form. The engine resolves it on apply (`internal/engine`):

- `fullchain_path` **and** `pem_key_path` set and both non-empty → concatenated into `${EASY_WAF_STATE_DIR}/certs/<id>/bundle.pem` (`internal/pemutil`). This is the ACME path.
- otherwise, `pem_crt_path` if set → used as-is, on the assumption that it already contains chain and key.
- otherwise → the certificate is **skipped** when the `crt-list` is built (`internal/haproxy/render.go`), which is why an incomplete certificate silently disappears from `:443` instead of failing loudly.
