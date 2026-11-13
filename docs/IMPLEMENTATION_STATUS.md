# Implementation status (Easy Home WAF)

**Last updated:** 2026-11-13

**Current VERSION:** 1.6.1 (see root `VERSION` file)
**Summary.** Capability tables (*Security hardening* … *Platform constraints*): Done — **36**, Partial — **0**, Missing — **0**, N/A — **0**. Acceptance criteria AC-01 … AC-10: Done — **8**, Partial — **2** (AC-03, AC-04). AC-05 is Done in containers; a real host remains a manual check.

This document records **what the appliance is required to do and where each
requirement is implemented** — the original MVP scope, the security work that
followed it, and the acceptance criteria AC-01 … AC-10 the project is judged
against. Statuses: **Done** | **Partial** | **Missing** | **N/A** (out of MVP /
deferred); **Partial** means the code is there and the remainder depends on the
environment (NAT, DNS, an SPOA package) or is deliberately outside the UI.

It is a status record, not a guide. How the system works is
[ARCHITECTURE.md](ARCHITECTURE.md); how to run it is
[OPERATIONS.md](OPERATIONS.md). The capability tables below are a compact index
and point at the feature sections (`see 7.*`) and at the acceptance criteria.

APT now belongs to internal `easy-waf-apt.service`, outside the management
broker cgroup. Real systemd/APT tests cover broker stop/SIGKILL with stable
operation/result, root-only worker access, self-upgrade, stopped public services
and removal of the owner's package. See [ADR 0008](adr/0008-apt-execution-service.md).
Full appliance installation and external ACME/WAN acceptance remain manual.

## Security hardening (audit follow-up)

| Item | Status | Where |
|------|--------|-------|
| **CSRF** | **Done** | JWT Bearer in `Authorization` (not cookies) + **`X-Requested-With: XMLHttpRequest`** on POST/PUT/PATCH/DELETE via `internal/api/csrf.go` (`RequireXHR`), UI `hdr()` in `internal/webui/dist/index.html`, docs `docs/ARCHITECTURE.md` / `docs/SECURITY.md`; authenticated curl clients set the header (`scripts/test-backup-restore.sh`, `scripts/smoke-appliance.sh`) |
| **Login rate limit** | **Done** | Per-IP sliding window **10 attempts / 5 min**, lockout **15 min**; `internal/api/ratelimit.go`, `handleLogin` in `internal/api/auth_handlers.go`, `LoginRL` wired in `internal/bootstrap/run.go` |
| **Hostname validation** | **Done** | `validateAppHostnames` on `POST /api/v1/applications` — `internal/api/validate_application.go` |
| **Mgmt ACL XFF spoofing** | **Done** | `TrustedRealIP` — forwarding headers trusted only from `EASY_WAF_TRUSTED_PROXY_CIDRS` (default loopback); `internal/api/realip.go` |
| **Host diag injection** | **Done** | `internal/host/diag` — host validation on Ping/Trace; `ping`/`traceroute`/`tracepath` use `--` before target; tests reject `-T`, `--port=22`, `; rm` |
| **IPBL SSRF guard** | **Done** | `internal/ipbl/ssrfguard.go` — hard floor (loopback/metadata/link-local/CGNAT always blocked) + granular `ipbl_fetch_allowed_cidrs` for RFC1918 feeds; dial-time anti–DNS rebinding; `POST /ipbl/sources` validates URL |
| **Split-DNS resilience** | **Done** | IPBL trusted CIDRs UI + `ipbl_fetch_allowed_cidrs`; HAProxy `resolvers easy_waf_dns` + `init-addr` for FQDN backends (`internal/haproxy/render.go`); `acme_dns_resolvers` for Lego DNS-01 propagation; [DNS.md](DNS.md) |
| **Host systemd whitelist** | **Done** | `AllowedUnit` / `AllowedAction` in `internal/host/systemd/allow.go`, with the allowlist the broker also enforces (`internal/host/systemdallow`); `host_handlers` 400 before privileged call |
| **SSH authorized_keys** | **Done** | `internal/host/users/sshkeys.go` — OpenSSH line regex; reject embedded newlines; no file write on invalid key |
| **Journal allowlist** | **Done** | `internal/host/journal` — only `-n`, `-u`, `--since`, `--until`, `-p`, `--no-pager`; unit on systemd whitelist |
| **Host management in GUI** | **Done** | **System** tab: services (allowlisted systemd), apt check/upgrade (**live NDJSON stream** via `POST /host/updates/upgrade/stream`), reboot/shutdown. **Network** tab: read-only overview; netplan + nftables **Advanced** apply with 90s safety window + **Keep changes** (commit); auto-revert via `systemd-run` → `easy-waf-hostd revert`. **Users** tab: list/create/delete local accounts, SSH keys editor. Form-based netplan/nft editors — next iteration. |
| **Realtime apt-upgrade log (NDJSON stream)** | **Done** | `apt-upgrade-stream` in `easy-waf-hostd`; API passthrough + System UI `fetch` stream |
| **System → Updates: autoremove (preview + live stream)** | **Done** | `apt-autoremove-simulate` / `apt-autoremove-stream`; shared apt single-flight; UI preview → confirm → `runAptStream` |
| **System → Updates: disk usage indicator + apt cache clean** | **Done** | `GET /host/disk` (`statfs` + cache/removable hints); `POST /host/updates/clean` (`apt-clean`); UI disk bar + Clean apt cache |
| **Host privilege model** | **Done** | Root broker **`easy-waf-hostd`** on `/run/easy-waf/hostd.sock`; `runner.Privileged` uses JSON over unix socket; API keeps `NoNewPrivileges`/`ProtectSystem=strict`; legacy sudo + `host-privileged.sh` removed on install |

## Core capabilities

| Requirement | Status | Where |
|-------------|--------|-------|
| Publish services by domain → backend | **Done** | see **7.1**; Host ACL → `use_backend` in `internal/haproxy/render.go` |
| TLS on HAProxy (crt-list, ACME/DB certs, SNI, HTTP→HTTPS) | **Done** | see **7.1**, **7.2**, **7.3**; single `crt-list` on `:443` (`internal/haproxy/render.go`), bundles from `internal/pemutil` |
| ACME issue / renew | **Done** | see **7.2**; `cmd/easy-waf-acmed`, `internal/acme`, `docs/ACME.md` |
| WebSocket (`Application.WebSocket`, `timeout tunnel`) | **Done** | see **7.3**; **AC-09** |
| Single HAProxy entry (`fe_http` / `fe_https`) | **Done** | see **7.3**; `internal/haproxy/render.go` |

## Security capabilities

| Requirement | Status | Where |
|-------------|--------|-------|
| Rate limit (stick-tables), per-app | **Done** | see **7.1a**; `internal/profiles`, `docs/SECURITY_PROFILES.md` |
| Basic WAF (ACL), per-app | **Done** | see **7.1a**; `internal/profiles`, `docs/APPLICATION_SECURITY.md` |
| CrowdSec + decisions (LAPI, decisions in UI) | **Done** | see **7.5** (ban/unban/whitelist in UI); `internal/crowdsec`, `docs/CROWDSEC.md` |
| SPOE bouncer | **Done** | see **7.3**; template `filter spoe` / `send-spoe-group`; `scripts/install.sh`, `docs/CROWDSEC.md` |
| Fail2Ban | **Done** | `GET/POST /api/v1/integrations/fail2ban/*` via **`easy-waf-hostd`** (`fail2ban` opcode); Fail2Ban UI tab; `docs/FAIL2BAN.md`; legacy socket/group path retired |
| GeoIP + cache (ipinfo, batch map, ACL) | **Done** | see **7.6**; `internal/geoip`, `docs/GEOIP.md` |

## UX and observability

| Requirement | Status | Where |
|-------------|--------|-------|
| Web UI (LAN): 12 tabs — dashboard, apps, certs, config, network, security, crowdsec, fail2ban, logs, system, users, settings | **Done** | see **7.7**; `internal/webui/dist/index.html` |
| Certificates, logs, stats, health | **Done** | see **7.7**, **7.8**; audit, `/health` (liveness), `/health/ready` (503 without PostgreSQL), `/status` |
| Backup/restore | **Done** | **AC-10**; `scripts/backup.sh`, `restore.sh`, E2E `scripts/test-backup-restore.sh` |

## Platform constraints

| Requirement | Status | Where |
|-------------|--------|-------|
| Ubuntu 24.04 LTS, systemd, nftables, AppArmor | **Done** | `scripts/install.sh`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md`, `docs/HOST-API.md` |
| `haproxy -c` before reload | **Done** | see **7.3**; `internal/apply`, `internal/engine` — but see the `EASY_WAF_SKIP_VALIDATE` caveat in `docs/OPERATIONS.md` |
| SPOE, WebSocket, SNI, redirect (golden + CI) | **Done** | see **7.3**; `internal/haproxy/testdata/golden/`, `.github/workflows/ci.yml` |
| CrowdSec LAPI not via Lua | **Done** | Go LAPI client (`internal/crowdsec`) + SPOA package; see **7.5**, `docs/CROWDSEC.md` |
| Config generator, validation, atomic apply, rollback | **Done** | see **7.3**; **AC-06** |
| GeoIP API + batch map + ACL | **Done** | see **7.6**; `GET/POST /api/v1/geoip/*`, `docs/GEOIP.md` |
| MaxMind MMDB as provider | **Done** | `geoip_mmdb_path`, `internal/geoip/maxmind.go`, `GET/POST /api/v1/geoip/*`, `docs/GEOIP.md`, `scripts/update-geoip-db.sh` |

## Features

### 7.1 App publishing — **Done** (CRUD API + UI, profiles, restricted paths, health path in model; **HTTP publishing**: per-app `listen_mode`, `fe_http` routing / per-host redirect, migration `012_listen_mode.sql`, golden `http-only-app` / `mixed-listen-modes` / `http-only-reverse-proxy`, audit `app_listen_mode_changed`)

### 7.1a Per-application security — **Done** (migration `009_application_security.sql`, `Application.security`, presets `internal/profiles/modes.go`, HAProxy per-host ACL order, per-app GeoIP maps `geoip_app_*.map`, API `GET/PUT/PATCH /applications/{id}/security`, `POST …/security/mode`, `GET /security/modes`, audit `app_security_mode_changed`, UI cards + Dashboard overview, golden `app-*` / `mixed-apps`, `docs/APPLICATION_SECURITY.md`)

### 7.2 ACME — **Done** (HTTP-01, DNS-01 providers, renew worker, apply hook in `easy-waf-acmed`; failed issuances retry with exponential backoff 10 min → 24 h, stale `issuing` rows are reclaimed — `internal/acme/retry.go`, `docs/ACME.md`. `notify_webhook_url` is an optional daily JSON POST from `easy-waf-acmed` when a certificate needs attention; empty leaves the journal warning only)

### 7.2a Global settings API — **Done** (`GET /api/v1/settings`; **`PATCH /api/v1/settings`** — partial JSON, merge over current in-memory/DB values; **`PUT /api/v1/settings`** — same merge so a partial body does not zero paths/timeouts; fields `geoip_cache_ttl` and `acme_renewal_interval` in JSON as `time.ParseDuration` strings, e.g. `"24h"`, `"30m"`, plus nanosecond numbers for older snapshots; UI saves ACME via PATCH) — `internal/api/server.go`, `internal/config/settings_merge.go`, `internal/config/duration.go`, `internal/webui/dist/index.html`

### 7.3 HAProxy engine — **Done** (template, checksum, validate, revisions/rollback, golden)

### 7.4 Security profiles — **Done** (profile names: `balanced`, `strict`, `trusted-lan`, `public-app`, `php-app`, `home-assistant`, `ha-mcp`, `none`, `custom`) — `internal/profiles/profiles.go`, `docs/SECURITY_PROFILES.md`

### 7.9 Path exposure and Home Assistant MCP — **Done** (migration `020_path_policy.sql`, `Application.path_policy`, allowlist 404, required header / edge token 401, per-path stick-table and `set-timeout server`, frontend `timeout client` when HAProxy 2.8 cannot set it per request, preset `ha-mcp`, golden `ha-mcp`, live test `TestLivePathPolicy`, UI path exposure, [HA-MCP.md](HA-MCP.md))

### 7.5 CrowdSec — **Done** (ping LAPI, decisions in UI, **Unban** / **Ban IP** / **Allow IP (whitelist)** via LAPI; `cscli` ops outside UI — per docs)

### 7.6 GeoIP — **Done** (`internal/geoip` — ipinfo + **MaxMind GeoLite2-Country.mmdb**, `GET /api/v1/geoip/lookup|stats|providers`, `POST /api/v1/geoip/reload`, settings `geoip_*` / `geoip_mmdb_path`, migrations `007`+`010`, batch `geoip_enforce.map` + ACL in `render.go`, UI section, `docs/GEOIP.md`)

### 7.7 UI pages — **Done** (tabs from the feature list above + audit/logs, certificate summary)

### 7.8 Statistics — **Done** (`internal/metrics` — HAProxy `show stat` over Unix socket, cache 5s; API `GET /api/v1/stats/haproxy`, `GET /api/v1/stats/summary`; Dashboard traffic + backends, refresh 10s; `haproxy_stats_socket_path` + golden template)

## Lessons learned

Captured in `docs/ARCHITECTURE.md`, `docs/CROWDSEC.md`, `internal/haproxy/render.go` (SNI, ws, validation).

## Acceptance criteria (AC-01 … AC-10)

Verified against code and scripts (iterations A–D).

| ID | Criterion | Status | Check in repository |
|----|-----------|--------|---------------------|
| **AC-01** | Install via `install.sh` on Ubuntu 24.04 LTS (full cycle: packages, layout, env, optional PostgreSQL, binaries, systemd) | **Done** | `scripts/install.sh` — `apt`, nftables, CrowdSec+SPOA packages, **LAPI bootstrap** (bouncers, `CROWDSEC_LAPI_*`, `-sync-settings-only`), `create_user_and_layout`, `install_env_file`, `systemctl enable --now easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service` (`EASY_WAF_ENABLE_SYSTEMD_UNITS`), units `packaging/systemd/*.service`, `WantedBy=multi-user.target` |
| **AC-02** | Add app via UI + Apply | **Done** | UI `#apps` → `POST /api/v1/applications`; `#config` → `POST /api/v1/apply`; `internal/api/server.go`, `internal/engine/engine.go` |
| **AC-03** | HTTPS certificate automatic (ACME) | **Partial** | `cmd/easy-waf-acmed` — issue/renew, on success `eng.Apply(ctx,"acme")`; needs `ACME_EMAIL`, DNS/HTTP-01, worker running (`docs/ACME.md`). Real Let's Encrypt is a manual check: [ACCEPTANCE.md](ACCEPTANCE.md) |
| **AC-04** | External access to published application | **Partial** | Render `fe_http`/`fe_https`, SNI, Host backends — **Done** in code; WAN/NAT/port-forward routing — outside the repo. Manual check: [ACCEPTANCE.md](ACCEPTANCE.md) |
| **AC-05** | CrowdSec blocks; HAProxy returns 403 for denied traffic | **Done** (containers) | The generated config sends each request to the bouncer and returns 403 for any remediation other than `allow` (`internal/haproxy/render.go`, `docs/CROWDSEC.md`); fails open. Proven against a real LAPI and bouncer by `scripts/test-crowdsec-e2e.sh`, nightly in `.github/workflows/e2e.yml`; a real host is still a manual check ([ACCEPTANCE.md](ACCEPTANCE.md)) |
| **AC-06** | Apply + rollback | **Done** | `engine.Apply` / `Rollback`, DB revisions; `POST /revisions/{id}/rollback`; UI Config (revisions table + button) |
| **AC-07** | UI: apps, certs, blocked | **Done** | Applications, Certificates (incl. summary/actions), Security (IPBL, blocked UA), Dashboard tabs |
| **AC-08** | Survives reboot | **Done** | `systemctl enable` for hostd/api/acmed (and optional CrowdSec); `Restart=on-failure` in unit files; api/acmed use `RestartSec=5` and `StartLimitIntervalSec=0`, so they keep retrying until a late PostgreSQL is up |
| **AC-09** | WebSocket (e.g. Home Assistant) | **Done** | `timeout tunnel` in defaults and for `websocket` in `internal/haproxy/render.go` |
| **AC-10** | Backup + restore | **Done** | `scripts/backup.sh`, `scripts/restore.sh`, `docs/BACKUP_RESTORE.md`, `scripts/test-backup-restore.sh` |

**AppArmor:** Ubuntu uses AppArmor by default; a dedicated easy-waf profile is not required. HAProxy access to configs is via the **`easy-waf`** group. Status: **Done** on Ubuntu 24.04.

## Roadmap (post-MVP)

1. **Release pipeline (basics done):** [`.github/workflows/release.yml`](../.github/workflows/release.yml) — push tag `v*`, `make build` for **amd64 and arm64**, tarball + `.deb` for each, `SHA256SUMS`, GitHub Release notes from `CHANGELOG.md`. Done since: `SHA256SUMS` signed with cosign, `-` tags published as pre-releases, nightly end-to-end runs in [`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml), and signed per-architecture Ubuntu 24.04 offline repository ISOs ([OFFLINE_BUNDLE.md](OFFLINE_BUNDLE.md)). The published 1.6.0 release is still amd64 only; arm64 and offline assets appear on the next tag.
2. **MaxMind MMDB (done):** see **`docs/GEOIP.md`**, **`scripts/update-geoip-db.sh`**. Next: MMDB signing, file size/epoch metrics.
3. ~~**CrowdSec in UI**~~ — done (ban/unban/whitelist).
4. ~~**Prometheus `/metrics`**~~ — done (`docs/MONITORING.md`).
5. ~~**Diagnostics bundle**~~ — done (`scripts/diagnostics.sh`, API bundle, `docs/DIAGNOSTICS.md`).
6. **OVA/OVF appliance template** for fast VM deployment. Signature WAF (Coraza/CRS) is a proposed ADR only: [docs/adr/0006-coraza-crs.md](adr/0006-coraza-crs.md).
7. **Smoke test checklist** — partly done: `scripts/smoke-appliance.sh` runs after installs and upgrades.
8. **Tests:** broader e2e — partly done: container runs for CrowdSec, the body policy and the real systemd/APT package-restart lifecycle in `.github/workflows/e2e.yml`; full appliance install/upgrade and real ACME are still checked by hand. The package lifecycle fixture uses a minimal package and fixture API/ACME workers (see [DEPLOYMENT.md](DEPLOYMENT.md)).
9. **UI:** optional separate frontend framework instead of a single `index.html`.

Update this file when closing MVP items and when `VERSION` changes.

## Golden tests: **Done**

`Render()` fixtures → snapshots `internal/haproxy/testdata/golden/<scenario>.cfg` + `<scenario>.crt-list.txt`; refresh: `make golden-update` (`UPDATE_GOLDEN=1`). Unit test: `go test ./internal/haproxy/... -run Golden`. Integration `haproxy -c` on golden files: `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (see `render_golden_integration_test.go`).

## CI (GitHub Actions)

| Requirement | Status | Where |
|-------------|--------|-------|
| `go vet`, golangci-lint, `go test -run Golden` (HAProxy golden), `go test -race` (with `-skip TestGoldenRender` to avoid duplicating golden), Linux artifact / LF checks for `scripts/**/*.sh`, `haproxy -c` on generated config + golden (`-tags=integration`), store/engine/auth integration tests against a PostgreSQL 16 service container | **Done** | `.github/workflows/ci.yml`, `internal/haproxy/render_golden_test.go`, `internal/haproxy/haproxy_validate_test.go` |
| Container end-to-end: the body policy and CrowdSec decisions against HAProxy 2.8 with a real LAPI and bouncer | **Done** | [`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml), nightly and on demand; `scripts/test-body-policy-e2e.sh`, `scripts/test-crowdsec-e2e.sh` |
