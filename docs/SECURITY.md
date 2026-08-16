# Security Guide

Applies to the release from root [`VERSION`](../VERSION) (**1.4.0**). Acceptance criteria for ACL / host firewall: [PROMPTS_ALIGNMENT.md](PROMPTS_ALIGNMENT.md) §9 (AC-01, AC-08).

## Principles

- **Least privilege**: user `easy-waf` owns `/var/lib/easy-waf` and generated files; HAProxy runs as `haproxy`; PostgreSQL uses a dedicated DB role with minimal privileges.
- **Secrets**: never commit real credentials. Use `/etc/easy-waf/easy-waf.env` (root, 0640) and `/var/lib/easy-waf/secrets/` (0700) for DNS env files and similar. Prefer **short-lived tokens** (Cloudflare API tokens with DNS-only scope).
- **AppArmor**: enforced by default on Ubuntu. Stock profile for `/usr/sbin/haproxy` is sufficient; no custom easy-waf profile required for MVP.
- **PostgreSQL**: use `sslmode=require` or `verify-full` to the DB in production; avoid `trust`/`password` on the wire in SME deployments.

## Control plane (API / UI)

- Default `install.sh` appliance: **management HTTPS** on **`EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443`** with management HTTP off. Default `install-interactive.sh` mode: **`https_loopback`** (`HTTP=off`, HTTPS `127.0.0.1:8443`) for SSH port-forwarding. **Cleartext management HTTP is off** unless you explicitly set **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`** (legacy loopback mode) or a non-loopback address **and** **`EASY_WAF_ALLOW_INSECURE_HTTP=1`** (legacy, logs a warning). **8443** uses a **bootstrap self-signed** cert (replace in UI / `PUT …/management-tls`). **nftables** (from **`install.sh`**) allows configured management ports only from **127.0.0.0/8** and **RFC1918** when **`EASY_WAF_NFT_MGMT_LAN=1`**. Separately, the installer opens **HAProxy edge** **80/tcp** and **443/tcp** when **`EASY_WAF_NFT_EDGE=1`** (default); set **`EASY_WAF_NFT_EDGE=0`** before install if another layer opens 80/443 only. Disable TLS listener: **`EASY_WAF_MANAGEMENT_HTTPS=0`** only after enabling loopback HTTP. Never forward management ports from WAN without VPN / reverse proxy / MFA.
- **`/health`** is JWT- and ACL-exempt on every **enabled** management listener (HTTPS `:8443` by default; loopback HTTP if you enabled it). **`/metrics`** stays ACL-gated and Prometheus-off by default. Scrape HTTPS `:8443` (self-signed) or loopback HTTP. ACME HTTP-01 stays on **`EASY_WAF_ACME_INTERNAL_HTTP`** (`127.0.0.1:8089`) and is **not** the management API.
- **Application-level ACL:** `management_allowed_cidrs` in global settings (API `GET` / `PATCH` / `PUT /api/v1/settings`; prefer **`PATCH`** for partial updates) restricts which source networks can use the UI and authenticated API (`/health` is exempt for probes). Defaults match RFC1918 + loopback; narrow the list in the configurator for stricter policy. Emergency: **`easy-waf-admin reset-control-panel-access`**, env **`EASY_WAF_BYPASS_MGMT_ACL=1`**, or see [ADMIN-CLI.md](ADMIN-CLI.md).
- **Reverse proxy / NAT:** `easy-waf-api` uses **`TrustedRealIP`** (`internal/api/realip.go`). Only the rightmost **`X-Forwarded-For`** value may rewrite `Request.RemoteAddr`, and only when the **TCP peer** (direct connection source) is in **`EASY_WAF_TRUSTED_PROXY_CIDRS`** (default **`127.0.0.0/8`** and **`::1/128`**). The trusted proxy must overwrite `X-Forwarded-For` with `$remote_addr`; `True-Client-IP` and `X-Real-IP` are ignored. A client that reaches `:8000` / `:8443` directly cannot bypass **`management_allowed_cidrs`** by sending `X-Forwarded-For: 127.0.0.1`. If NGINX or another proxy runs on a non-loopback LAN address, add that proxy’s CIDR or `/32` to **`EASY_WAF_TRUSTED_PROXY_CIDRS`** (comma-separated). Still restrict who can reach the management listener (nftables, no WAN forward).
- First boot: there is **no** shared `admin`/`admin` password. After `easy-waf-api` starts with an empty `users` table, a one-time enrollment secret is written to **`$EASY_WAF_STATE_DIR/secrets/enrollment`** (mode **0600**). Print it locally as root with **`easy-waf-admin print-enrollment`** (stdout only; never journal). Then **`POST /api/v1/auth/enroll`** (or the UI enrollment form) with that secret, a username, and a password (≥8 characters). The secret is hashed in PostgreSQL, deleted from disk after success, and cannot be reused. Existing operators are never reset. Optional **`EASY_WAF_ADMIN_TOKEN`** is for automation only (legacy Bearer) — prefer session JWT from **`POST /api/v1/auth/login`**. Changing the operator password increments **`users.session_version`** and immediately rejects previously issued JWTs.
- **Package rollback safety:** never start a pre-enrollment binary against a database where `users` is empty or enrollment is pending; older binaries can recreate the legacy `admin/admin` account. Complete enrollment or restore an operator-bearing database backup first. When rolling back to a binary that does not enforce `users.session_version`, rotate `$EASY_WAF_STATE_DIR/secrets/jwt.secret` (or `EASY_WAF_JWT_SECRET`) before startup so password-revoked JWTs cannot become valid again.
- **Sign-out revokes server-side.** **`POST /api/v1/auth/logout`** increments **`users.session_version`**, so every JWT already issued to that operator stops working immediately — clearing `sessionStorage` alone left a captured token valid for its full 24-hour TTL. The UI calls it before dropping the local token; use it after logging in from a machine you do not control. Legacy automation tokens have no session and return **400**.
- **Session JWTs must carry `exp`.** `ParseJWT` uses `WithExpirationRequired()`, so a signed token without an expiry is rejected instead of living forever.
- **`POST /api/v1/auth/change-password`** is covered by the same per-IP limiter as login: it verifies `current_password`, so it must not be an unthrottled password oracle.
- **Login does not reveal which operator names exist.** An unknown username runs a dummy bcrypt comparison, so it takes the same time as a wrong password. (`enrollment required` is appliance-wide state that unauthenticated `GET /auth/status` already returns.)
- **GeoIP database upload (`POST /api/v1/geoip/database`)** is the only route exempt from the global 4 MiB body limit, and it applies its own 128 MiB cap in the handler. The destination is derived from the database's own metadata inside `<state>/geoip/` — never from the request — the archive format is detected from the content rather than a file name, `.tar.gz` member paths are ignored, and the file must open as a MaxMind database and answer a probe lookup before an atomic rename puts it in place. A rejected upload leaves the running database untouched. Installs are serialized and audited (`geoip_database_uploaded`). See [GEOIP.md](GEOIP.md).
- **`EASY_WAF_JWT_SECRET` must be at least 32 characters**, and the check runs where the secret is loaded and again on both signing and verification. Leave it unset and a 32-byte random key is generated in **`$EASY_WAF_STATE_DIR/secrets/jwt.secret`** (mode **0600**) — that is the recommended setup; set it explicitly only when several appliances must share sessions. It had no minimum before, while `SignJWT` refused to sign below 16 bytes: a short operator-set value produced an appliance nobody could log into and anybody who guessed the secret could forge sessions for, with no password check, no rate limit and no failed-login audit record.
- **`/metrics` can require its own token.** Set **`EASY_WAF_METRICS_TOKEN`** (≥16 characters) and have Prometheus send it as `Authorization: Bearer …`. Without it the endpoint is protected only by `management_allowed_cidrs`, which defaults to all of RFC1918 — every LAN host can read appliance metrics when `PrometheusEnabled` is on.
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
- **CrowdSec** + **SPOE bouncer**: keep engine names aligned between `haproxy.cfg` and SPOE file; rotate LAPI keys on compromise. LAPI URL destination policy defaults to loopback `:8080`; extra origins via **`CROWDSEC_LAPI_ALLOWED_ORIGINS`**.
- **HTTP and HTTPS vhosts** share the same per-application security block (IP lists, GeoIP, bot/UA, WAF, methods, path ACLs, CrowdSec). Rate limiting stays on the backend once per request. ACME `/.well-known/acme-challenge/` is excluded on `:80`.
- **HTTPS backends:** new apps default to **`ssl verify required`** with **`/etc/ssl/certs/ca-certificates.crt`** (or an allowlisted CA under `/etc/easy-waf/ca/` or `$stateDir/ca/`). **`backend_tls_verify=none`** is an explicit legacy override (API warning + audit `backend_tls_verify_disabled`). Never-migrated legacy HTTPS rows are intentionally initialized to `none` so upgrades do not outage. Appliances that ran the original migration 018 before the repeat-safety fix may also have had an operator-selected `required` value reset to `none`; after upgrade, review every HTTPS backend currently stored as `none` and restore `required` where appropriate.
- **Fail2Ban**: protect SSH; optional jails for management ports if exposed.

## ACME / DNS-01

- Store provider credentials in **root-only env files** referenced by `dns_credentials_env_file`, not in the database.
- Prefer **restricted API tokens** (Cloudflare DNS edit on one zone only; AWS IAM policy scoped to Route53 on required zones).

## Audit

- Administrative actions are logged in PostgreSQL `audit_log` and should be forwarded to central SIEM in SME setups.

## Host management (`/api/v1/host/*`)

- **Privilege model:** **`easy-waf-hostd`** runs as **root** on **`/run/easy-waf/hostd.sock`** (`root:easy-waf` **0660**). **`easy-waf-api`** keeps **`NoNewPrivileges=true`** and **`ProtectSystem=strict`**; it does **not** use `sudo` or `/usr/lib/easy-waf/host-privileged.sh`. Each request is JSON `{"argv":["opcode",…]}`; the broker dispatches only known opcodes via a **`switch`** (never `sh -c`, never blind `exec(argv…)`). Linux peers are checked with **`SO_PEERCRED`** (uid `easy-waf` or root).
- **Netplan / nftables rollback window:** GUI paths use `POST …/netplan/apply` and `POST …/firewall/apply-rollback` with `rollback_seconds` (clamped **30–600**, default **90**). The broker backs up under `/var/lib/easy-waf/rollback/`, applies, then **`systemd-run`** → **`/usr/sbin/easy-waf-hostd revert <kind> <token>`**. Revert does not depend on API or the long-lived broker. `POST …/commit` cancels the timer. Invalid YAML/ruleset is rejected before any timer is scheduled.
- **Nothing the broker touches under `/var/lib/easy-waf` follows a symlink.** That directory is owned by the unprivileged `easy-waf` account — it has to be, since `easy-waf-api` writes generated configuration there — so every path in it is attacker-controlled under this threat model. Rollback backups, staged files and the apt action log are opened relative to the **state directory itself** with `openat2` (`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`); `/var/lib` is root-owned, so that one directory entry cannot be swapped. Resolving these paths normally gave root file disclosure (a backup pointed at `/etc/shadow`, copied into a 0644 file the same account can read) and root truncation of any file (the log opened with `O_TRUNC`). Note that anchoring *inside* the tree is not enough: `RESOLVE_BENEATH` constrains what happens below an open descriptor and cannot undo a symlink followed while obtaining it.
- **systemd:** `POST /host/services/{unit}/{action}` — allowlists in API and broker (`internal/host/systemd/allow.go`); unknown values return **400** before the broker runs.
- **journal:** `GET /host/journal` builds `journalctl` arguments from an allowlist in Go (`internal/host/journal`); unit names use the same whitelist as systemd. Bash in `privileged.sh` still rejects shell metacharacters in journal args.
- **Diagnostics:** `POST /host/diagnostics/ping` and `…/trace` validate hostnames/IPs like Ping; commands use a **`--`** separator before the target host so values such as `-T` or `--port=22` cannot be interpreted as flags.
- **SSH keys:** `PUT /host/users/{name}/ssh-keys` validates each line (`ssh-rsa` / `ssh-ed25519` / `ecdsa-sha2-*` + base64); invalid or multiline payloads are rejected before writing `authorized_keys`. The **broker repeats the same validation** (`hostspec.ValidateAuthorizedKeysContent`) — the API-side check is advisory, since a compromised `easy-waf-api` can talk to the socket directly. A line may not begin with an options field (`command=`, `environment=`, `permitopen=`, …), because options execute code as the account owner on every login.
  - **Privileged targets are refused by default:** an account in `root`, `sudo`, `admin` or `wheel` cannot receive keys, since that would convert control of `easy-waf-api` into root on the appliance. Opt in with `Environment=EASY_WAF_HOSTD_ALLOW_PRIVILEGED_SSH_TARGETS=1` in the **`easy-waf-hostd`** unit (root-owned — the API cannot set it). An unreadable `/etc/group` fails closed.
  - Writes never follow a symlink: `~/.ssh` and `authorized_keys` are opened relative to the home directory with `openat2` (`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`), ownership and mode are set through the descriptor, and the key file is replaced by `renameat` so a failed write cannot truncate it. Previously `install -d -o user ~/.ssh` resolved the path as root, so an account could point its own `~/.ssh` at another directory and have root chown it.
  - The `easy-waf-hostd` unit ships with **`ProtectHome=false`** because the broker has to reach `~/.ssh`; with `ProtectHome=true` systemd shows `/home` as empty to the service and this endpoint silently cannot write anything. The exposure is covered by the three controls above (broker-side validation, refusal of root-equivalent targets, symlink-free writes) rather than by hiding the directory. If you never manage keys from the UI, setting `ProtectHome=true` back is a safe extra layer.
- **Power / apt / nft / netplan:** only fixed opcodes via **`easy-waf-hostd`** (no arbitrary shell).
- **Fail2ban:** `GET/POST /api/v1/integrations/fail2ban/*` uses broker opcode **`fail2ban`** with a strict allowlist (`ping`, `status`, `status <jail>`, `set <jail> unbanip <ip>`); jail/IP validated in **`internal/host/hostspec`**. Legacy fail2ban group/socket/sudoers access is retired.

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

- Build binaries in **reproducible** CI; publish **SHA256** checksums with releases. `release.yml` uploads **`SHA256SUMS`** next to every release tarball.
- **Downloads are verified, not just TLS-protected.** `scripts/install.sh` and `scripts/download-release.sh` fetch `SHA256SUMS` from the same release and refuse any artifact whose digest is missing or does not match — release binaries are installed to `/usr/sbin` as root, so a typosquatted `EASY_WAF_GITHUB_REPO`, a poisoned asset or a TLS-stripping proxy would otherwise mean root code execution. On failure the installer **builds from source** instead.
  - `curl` runs with `--proto '=https' --proto-redir '=https' --tlsv1.2`: no plaintext hop, not even through a redirect.
  - Artifacts are downloaded into `mktemp -d`, never a predictable `/tmp` path (root `curl -o` follows symlinks). The same applies to every root-executed script: **`scripts/smoke-appliance.sh`** writes its scratch files into `mktemp -d` with a cleanup trap, because `postinst` tells the operator to run it after each upgrade and PID-suffixed `/tmp` names are cheap to pre-create as symlinks.
  - **`scripts/restore.sh`** refuses an archive containing absolute or `..` member paths, and matches the listing with a here-string rather than a pipe. `tar -tzf … | grep -q` under `set -o pipefail` fails **open**: grep exits at the first match, tar dies of SIGPIPE, the pipeline reports failure, and the malicious archive is extracted anyway.
  - `EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1` overrides the check (mirrors without `SHA256SUMS`) — logs a loud warning; do not use in production.
  - `EASY_WAF_RELEASE_URL` requires an explicit `EASY_WAF_RELEASE_SHA256=<hex>`.
  - Offline regression tests for the verifier: `make test-release-verify`.
- For OVF/OVA: verify image checksum after download; do not run golden images past EOL without patching.

## Quick checklist (production)

- [ ] `EASY_WAF_ADMIN_TOKEN` rotated; `EASY_WAF_DEV` unset  
- [ ] `DATABASE_URL` uses TLS to PostgreSQL where applicable  
- [ ] Management API not on `0.0.0.0` facing WAN  
- [ ] **nftables** / cloud security groups: 22 from admin IPs only; 80/443 for edge  
- [ ] SSH: keys only, `PermitRootLogin no`  
- [ ] CrowdSec + HAProxy SPOE tested after upgrades  
- [ ] Backups: `pg_dump` + `/var/lib/easy-waf` + `/etc/easy-waf` — see [BACKUP_RESTORE.md](BACKUP_RESTORE.md)  
