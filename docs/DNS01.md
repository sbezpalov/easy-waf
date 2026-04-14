# DNS-01 (Lego providers)

Certificates with `mode: dns-01` use **Lego** DNS providers. Secrets are **not** stored in PostgreSQL: set `dns_credentials_env_file` to a **Linux path** readable only by `easy-waf` (e.g. mode `0600`), containing `KEY=value` lines consumed by Lego’s env helpers.

Default **`dns_provider`** when empty: **`cloudns`** (ClouDNS).

## Providers

| `dns_provider` | Lego package | Typical variables in env file |
|----------------|--------------|-------------------------------|
| `cloudns` | ClouDNS | `CLOUDNS_AUTH_ID`, `CLOUDNS_AUTH_PASSWORD` (or `CLOUDNS_SUB_AUTH_ID`) |
| `cloudflare` | Cloudflare | `CLOUDFLARE_DNS_API_TOKEN` (recommended) or `CLOUDFLARE_EMAIL` + `CLOUDFLARE_API_KEY` |
| `route53` | AWS Route53 | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`; optional `AWS_HOSTED_ZONE_ID` |
| `webhook` | HTTP (`httpreq`) | `HTTPREQ_ENDPOINT` (base URL), optional `HTTPREQ_MODE=RAW`, `HTTPREQ_USERNAME`, `HTTPREQ_PASSWORD` |

See upstream Lego docs for each provider: [https://go-acme.github.io/lego/dns/](https://go-acme.github.io/lego/dns/)

## Webhook (`dns_provider: webhook`)

Lego posts JSON to `{HTTPREQ_ENDPOINT}/present` and `{HTTPREQ_ENDPOINT}/cleanup` (unless `HTTPREQ_MODE=RAW`). Your service must create/delete `_acme-challenge` TXT records accordingly.

## Flow

1. Create env file under e.g. `/var/lib/easy-waf/secrets/dns/<cert-id>.env`.
2. `POST /api/v1/certificates` with `mode`, `dns_provider`, `dns_credentials_env_file`, then `POST /api/v1/certificates/{id}/request-issue` with the same mode or rely on stored row.
3. `easy-waf-acmed` loads the env file, applies variables, runs Lego DNS-01, writes PEMs, applies HAProxy.

## SME / HA

Use the same env file on a shared filesystem, or duplicate secrets per node (rotation via automation). Database holds only the **path**, not the secret.
