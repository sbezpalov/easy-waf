# Security Guide

Актуально для релиза из корневого [`VERSION`](../VERSION) (**1.0.0**). Критерии приёмки по ACL / host firewall: [PROMPTS_ALIGNMENT.md](PROMPTS_ALIGNMENT.md) §9 (AC-01, AC-08).

## Principles

- **Least privilege**: user `easy-waf` owns `/var/lib/easy-waf` and generated files; HAProxy runs as `haproxy`; PostgreSQL uses a dedicated DB role with minimal privileges.
- **Secrets**: never commit real credentials. Use `/etc/easy-waf/easy-waf.env` (root, 0640) and `/var/lib/easy-waf/secrets/` (0700) for DNS env files and similar. Prefer **short-lived tokens** (Cloudflare API tokens with DNS-only scope).
- **AppArmor**: enforced by default on Ubuntu. Stock profile for `/usr/sbin/haproxy` is sufficient; no custom easy-waf profile required for MVP.
- **PostgreSQL**: use `sslmode=require` or `verify-full` to the DB in production; avoid `trust`/`password` on the wire in SME deployments.

## Control plane (API / UI)

- Default appliance: **`EASY_WAF_LISTEN_HTTP=0.0.0.0:8000`**, **`EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443`**. **8443** uses a **bootstrap self-signed** cert (replace in UI / `PUT …/management-tls`). **nftables** (from **`install.sh`**) allows **8000/tcp** and **8443/tcp** only from **127.0.0.0/8** and **RFC1918** when **`EASY_WAF_NFT_MGMT_LAN=1`**. Separately, the installer opens **HAProxy edge** **80/tcp** and **443/tcp** when **`EASY_WAF_NFT_EDGE=1`** (default); set **`EASY_WAF_NFT_EDGE=0`** before install if another layer opens 80/443 only. Loopback-only management: `127.0.0.1:8000` + `127.0.0.1:8443` and **`EASY_WAF_NFT_MGMT_LAN=0`**. Disable TLS listener: **`EASY_WAF_MANAGEMENT_HTTPS=0`**. Never forward management ports from WAN without VPN / reverse proxy / MFA.
- **Application-level ACL:** `management_allowed_cidrs` in global settings (API `GET` / `PATCH` / `PUT /api/v1/settings`; prefer **`PATCH`** for partial updates) restricts which source networks can use the UI and authenticated API (`/health` is exempt for probes). Defaults match RFC1918 + loopback; narrow the list in the configurator for stricter policy. Emergency: **`easy-waf-admin reset-control-panel-access`**, env **`EASY_WAF_BYPASS_MGMT_ACL=1`**, or see [ADMIN-CLI.md](ADMIN-CLI.md).
- **Reverse proxy / NAT:** `easy-waf-api` uses **`TrustedRealIP`** (`internal/api/realip.go`). Forwarding headers (**`True-Client-IP`**, **`X-Real-IP`**, leftmost **`X-Forwarded-For`**) rewrite `Request.RemoteAddr` **only** when the **TCP peer** (direct connection source) is in **`EASY_WAF_TRUSTED_PROXY_CIDRS`** (default **`127.0.0.0/8`** and **`::1/128`**). A client that reaches `:8000` / `:8443` directly cannot bypass **`management_allowed_cidrs`** by sending `X-Forwarded-For: 127.0.0.1`. If NGINX or another proxy runs on a non-loopback LAN address, add that proxy’s CIDR or `/32` to **`EASY_WAF_TRUSTED_PROXY_CIDRS`** (comma-separated). Still restrict who can reach the management listener (firewalld, no WAN forward).
- Sign in to the management UI with local user **`admin`** (initial password **`admin`**) and **change the password** on first login (enforced by API until changed). Optional **`EASY_WAF_ADMIN_TOKEN`** is for automation only (legacy Bearer) — prefer session JWT from **`POST /api/v1/auth/login`**.
- Management HTTPS is served by **easy-waf-api** on **8443** (bootstrap self-signed; replace in UI). Edge traffic is handled by HAProxy.
- Plan for **MFA** at the reverse proxy (e.g. OAuth2 proxy) if the UI must be reachable beyond strict LAN.

## CSRF Protection

The management API uses **JWT Bearer tokens** in the `Authorization` header, stored in `sessionStorage` (not cookies). Browsers do not attach custom headers automatically on cross-origin form submissions or link navigations, which makes traditional CSRF attacks ineffective against this API.

As an additional defense-in-depth measure, the API requires a **`X-Requested-With: XMLHttpRequest`** header on all state-changing requests (POST, PUT, PATCH, DELETE). Requests without this header receive **403 Forbidden**. This reduces risk from contexts where custom headers cannot be set (e.g. `<form>` submissions, `<img>` tags, basic redirects).

The `/health` endpoint and `GET` requests are exempt from this check.

## Edge (HAProxy / CrowdSec)

- **File access:** easy-waf generated configs under **`/var/lib/easy-waf/haproxy/`** (and TLS material under **`/var/lib/easy-waf/certs/`**) are readable by user **`haproxy`** via membership in group **`easy-waf`** and directory mode **0750**. After manual file copies or restores, run **`sudo bash scripts/fix-haproxy-easy-waf-dropin.sh`**.
- When an **NGFW** (MikroTik, FortiGate, …) sits in front of the appliance, use **IPS** and **application control** on the firewall; the WAF handles hostname routing, TLS, CrowdSec, and IPBL — see **Reference topology: NGFW → WAF** in [ARCHITECTURE.md](ARCHITECTURE.md).
- Only **80/443** (and SSH management) should be reachable from untrusted networks; use **nftables** (managed ruleset **`/etc/nftables/easy-waf.nft`**) or cloud security groups.
- **CrowdSec** + **SPOE bouncer**: keep engine names aligned between `haproxy.cfg` and SPOE file; rotate LAPI keys on compromise.
- **Fail2Ban**: protect SSH; optional jails for management ports if exposed.

## ACME / DNS-01

- Store provider credentials in **root-only env files** referenced by `dns_credentials_env_file`, not in the database.
- Prefer **restricted API tokens** (Cloudflare DNS edit on one zone only; AWS IAM policy scoped to Route53 on required zones).

## Audit

- Administrative actions are logged in PostgreSQL `audit_log` and should be forwarded to central SIEM in SME setups.

## Host management (`/api/v1/host/*`)

- **Netplan / nftables rollback window:** GUI and recommended API paths use `POST …/netplan/apply` and `POST …/firewall/apply-rollback` with `rollback_seconds` (clamped **30–600**, default **90**). The helper backs up the previous file under `/var/lib/easy-waf/rollback/`, applies the staged change, then starts a **transient `systemd-run` unit** that invokes `netplan-revert` or `nft-revert` after the timeout. **Revert does not depend on `easy-waf-api`** staying up — important when a bad network change drops the management session. `POST …/commit` with `{ "token" }` cancels the timer and removes the backup. Tokens are hex (`^[a-f0-9]{8,64}$`); invalid YAML/ruleset is rejected in Go (`nft -c`) or in the helper (`netplan generate`) **before** any timer is scheduled.
- **systemd:** `POST /host/services/{unit}/{action}` accepts only units and actions whitelisted in Go (`internal/host/systemd/allow.go`) and in `scripts/host/privileged.sh` — unknown values return **400** before the privileged helper runs.
- **journal:** `GET /host/journal` builds `journalctl` arguments from an allowlist in Go (`internal/host/journal`); unit names use the same whitelist as systemd. Bash in `privileged.sh` still rejects shell metacharacters in journal args.
- **Diagnostics:** `POST /host/diagnostics/ping` and `…/trace` validate hostnames/IPs like Ping; commands use a **`--`** separator before the target host so values such as `-T` or `--port=22` cannot be interpreted as flags.
- **SSH keys:** `PUT /host/users/{name}/ssh-keys` validates each line (`ssh-rsa` / `ssh-ed25519` / `ecdsa-sha2-*` + base64); invalid or multiline payloads are rejected before writing `authorized_keys`.
- **Power / apt / nft / netplan:** only fixed subcommands via `host-privileged.sh` (no arbitrary shell).

## Outbound requests (IPBL external feeds)

- **IPBL external feeds** (`internal/ipbl/ssrfguard.go`): URLs must use **http** or **https**. Resolved and dial-time addresses are checked in two layers:
  - **Hard floor (always blocked):** loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`, `fe80::/10`), unspecified, **CGNAT (100.64.0.0/10)** — including cloud metadata (**169.254.169.254**). These cannot be overridden by any allowlist (protects local PostgreSQL, metadata APIs).
  - **Soft (RFC1918 private):** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` — blocked unless the IP is inside **`ipbl_fetch_allowed_cidrs`** (granular allowlist for split-DNS internal feeds). Empty allowlist = **public feeds only** (secure default).
- **DNS rebinding:** the HTTP transport uses a **dial-time** IP re-check so a hostname that was public at validation time cannot connect to a private address later.
- **Redirects:** each redirect target is re-validated (max 5 hops).
- **Split-DNS example:** feed at `http://blocklist.lan/list.txt` resolving to `192.168.1.50` — set `ipbl_fetch_allowed_cidrs: ["192.168.1.0/24"]`. Do **not** use deprecated **`ipbl_allow_private_fetch`** in production; it opens all RFC1918 when the CIDR list is empty.
- Adding a source via **`POST /api/v1/ipbl/sources`** validates the URL immediately (**400** on blocked hosts). Sync skips bad sources and records the reason on the source row (`last_fetch_error`).
- When **`ipbl_external_enabled`** is **false** (air-gapped), no outbound feed fetch runs.

See [DNS.md](DNS.md) for HAProxy backend DNS and ACME DNS-01 in split-DNS environments.

## IPBL and GeoIP

- External blocklist URLs: treat as untrusted input; line format is validated after download. Prefer allowlisting your office IPs for break-glass access.

## Supply chain

- Build binaries in **reproducible** CI; publish **SHA256** checksums with releases.
- For OVF/OVA: verify image checksum after download; do not run golden images past EOL without patching.

## Quick checklist (production)

- [ ] `EASY_WAF_ADMIN_TOKEN` rotated; `EASY_WAF_DEV` unset  
- [ ] `DATABASE_URL` uses TLS to PostgreSQL where applicable  
- [ ] Management API not on `0.0.0.0` facing WAN  
- [ ] **nftables** / cloud security groups: 22 from admin IPs only; 80/443 for edge  
- [ ] SSH: keys only, `PermitRootLogin no`  
- [ ] CrowdSec + HAProxy SPOE tested after upgrades  
- [ ] Backups: `pg_dump` + `/var/lib/easy-waf` + `/etc/easy-waf` — see [BACKUP_RESTORE.md](BACKUP_RESTORE.md)  
