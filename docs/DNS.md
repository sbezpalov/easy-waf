# DNS in easy-waf (split-DNS considerations)

Many SME deployments use **split-DNS**: internal forwarders resolve `*.lan` / RFC1918 names, while public names use upstream or ISP DNS. easy-waf touches DNS in three places; each can misbehave if only the internal view is used where the **public** view is required.

## IPBL external feed fetch

- **What:** `easy-waf-api` resolves feed hostnames and fetches HTTP(S) lists. Feeds are fetched on **apply** and on explicit `POST /api/v1/ipbl/sync` — there is no scheduled background refresh, so a feed is only as fresh as the last apply or sync.
- **Default:** only **public** destination IPs are allowed after resolve and at dial time (anti–DNS rebinding).
- **Internal feeds:** set global **`ipbl_fetch_allowed_cidrs`** (UI: Security → IP Blacklist → *Trusted internal CIDRs for feed fetch*) to RFC1918 ranges that host your blocklist, e.g. `192.168.1.0/24`.
- **Hard floor (never allowlisted):** loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), unspecified, CGNAT `100.64.0.0/10`, and multicast (including link-local multicast). This blocks `127.0.0.1:5432` and cloud metadata even if someone adds those CIDRs to the allowlist.
- **Air-gapped:** `ipbl_external_enabled: false` — no outbound fetch at all.

See [IPBL.md](IPBL.md) and [SECURITY.md](SECURITY.md).

## HAProxy backend by hostname

- **What:** when `backend_host` is a **DNS name** (not a literal IP), generated HAProxy config includes `resolvers easy_waf_dns` with `parse-resolv-conf` (system `/etc/resolv.conf`, including split-DNS forwarders) and `init-addr last,libc,none` on the server line.
- **Why:** backends on DHCP/LAN can change IP; HAProxy can start even if DNS is briefly down (`init-addr`).
- **Literal IP backends:** no resolvers block (unchanged).

Ensure `/etc/resolv.conf` on the appliance points at resolvers that can resolve your internal backend names.

## ACME DNS-01 propagation check

- **What:** `easy-waf-acmed` uses Lego to publish TXT records and **poll public DNS** until the challenge is visible.
- **Split-DNS risk:** if propagation checks use an internal forwarder that does not see the public TXT record, issuance can hang or fail.
- **Fix:** set **`acme_dns_resolvers`** in global settings to public resolvers, e.g. `["1.1.1.1:53","8.8.8.8:53"]`. Empty = system resolver (same as `/etc/resolv.conf`).

See [ACME.md](ACME.md).

## Quick checklist

| Component | Setting | Split-DNS tip |
|-----------|---------|----------------|
| IPBL fetch | `ipbl_fetch_allowed_cidrs` | Allow only LAN ranges that host feeds; never loopback/metadata |
| HAProxy backend | `backend_host` FQDN | Use system resolvers via `parse-resolv-conf` |
| ACME DNS-01 | `acme_dns_resolvers` | Use public resolvers for propagation checks |

Deprecated: **`ipbl_allow_private_fetch`** — when `true` and `ipbl_fetch_allowed_cidrs` is empty, allows all RFC1918 for feeds only (not loopback/metadata). Prefer explicit CIDRs.
