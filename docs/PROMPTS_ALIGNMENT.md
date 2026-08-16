# Alignment with `prompts.md` (Easy Home WAF)

**Last updated:** 2026-04-20  
**Current VERSION:** 1.2.1 (see root `VERSION` file)
**Summary for §2–§3 table rows:** Done — **20**, Partial — **1**, Missing — **0**, N/A — **0**

This document **maps** requirements from [prompts.md](../prompts.md) to repository code and docs. Statuses: **Done** | **Partial** | **Missing** | **N/A** (out of MVP / deferred).

Source of truth for implementation is **§7 Features**; acceptance checks are **§9 Acceptance criteria**. Sections §2–§3 below are a compact index with status and pointers to `see §7.*` / §9 when needed.

## Security hardening (audit follow-up)

| Item | Status | Where |
|------|--------|-------|
| **CSRF** | **Done** | JWT Bearer in `Authorization` (not cookies) + **`X-Requested-With: XMLHttpRequest`** on POST/PUT/PATCH/DELETE via `internal/api/csrf.go` (`RequireXHR`), UI `hdr()` in `internal/webui/dist/index.html`, docs `docs/ARCHITECTURE.md` / `docs/SECURITY.md`; curl scripts set the header (`scripts/restore.sh`, `scripts/test-backup-restore.sh`, `scripts/update-geoip-db.sh`) |
| **Login rate limit** | **Done** | Per-IP sliding window **10 attempts / 5 min**, lockout **15 min**; `internal/api/ratelimit.go`, `handleLogin` in `internal/api/auth_handlers.go`, `LoginRL` wired in `internal/bootstrap/run.go` |
| **Hostname validation** | **Done** | `validateAppHostnames` on `POST /api/v1/applications` — `internal/api/validate_application.go` |
| **Mgmt ACL XFF spoofing** | **Done** | `TrustedRealIP` — forwarding headers trusted only from `EASY_WAF_TRUSTED_PROXY_CIDRS` (default loopback); `internal/api/realip.go` |
| **Host diag injection** | **Done** | `internal/host/diag` — host validation on Ping/Trace; `ping`/`traceroute`/`tracepath` use `--` before target; tests reject `-T`, `--port=22`, `; rm` |
| **IPBL SSRF guard** | **Done** | `internal/ipbl/ssrfguard.go` — hard floor (loopback/metadata/link-local/CGNAT always blocked) + granular `ipbl_fetch_allowed_cidrs` for RFC1918 feeds; dial-time anti–DNS rebinding; `POST /ipbl/sources` validates URL |
| **Split-DNS resilience** | **Done** | IPBL trusted CIDRs UI + `ipbl_fetch_allowed_cidrs`; HAProxy `resolvers easy_waf_dns` + `init-addr` for FQDN backends (`internal/haproxy/render.go`); `acme_dns_resolvers` for Lego DNS-01 propagation; [DNS.md](DNS.md) |
| **Host systemd whitelist** | **Done** | `AllowedUnit` / `AllowedAction` in `internal/host/systemd/allow.go` (parity with `privileged.sh`); `host_handlers` 400 before privileged call |
| **SSH authorized_keys** | **Done** | `internal/host/users/sshkeys.go` — OpenSSH line regex; reject embedded newlines; no file write on invalid key |
| **Journal allowlist** | **Done** | `internal/host/journal` — only `-n`, `-u`, `--since`, `--until`, `-p`, `--no-pager`; unit on systemd whitelist |
| **Host management in GUI** | **Done** | **System** tab: services (allowlisted systemd), apt check/upgrade (**live NDJSON stream** via `POST /host/updates/upgrade/stream`), reboot/shutdown. **Network** tab: read-only overview; netplan + nftables **Advanced** apply with 90s safety window + **Keep changes** (commit); auto-revert via `systemd-run` → `easy-waf-hostd revert`. **Users** tab: list/create/delete local accounts, SSH keys editor. Form-based netplan/nft editors — next iteration. |
| **Realtime apt-upgrade log (NDJSON stream)** | **Done** | `apt-upgrade-stream` in `easy-waf-hostd`; API passthrough + System UI `fetch` stream |
| **System → Updates: autoremove (preview + live stream)** | **Done** | `apt-autoremove-simulate` / `apt-autoremove-stream`; shared apt single-flight; UI preview → confirm → `runAptStream` |
| **System → Updates: disk usage indicator + apt cache clean** | **Done** | `GET /host/disk` (`statfs` + cache/removable hints); `POST /host/updates/clean` (`apt-clean`); UI disk bar + Clean apt cache |
| **Host privilege model** | **Done** | Root broker **`easy-waf-hostd`** on `/run/easy-waf/hostd.sock`; `runner.Privileged` uses JSON over unix socket; API keeps `NoNewPrivileges`/`ProtectSystem=strict`; legacy sudo + `host-privileged.sh` removed on install |

## §2 Goals — Core

| Requirement | Status | Where |
|-------------|--------|-------|
| Publish services by domain → backend | **Done** | see **§7.1** |
| TLS on HAProxy (crt-list, ACME/DB certs, SNI, HTTP→HTTPS) | **Done** | see **§7.1**, **§7.2**, **§7.3** |
| ACME issue / renew | **Done** | see **§7.2** |
| WebSocket (`Application.WebSocket`, `timeout tunnel`) | **Done** | see **§7.3**; **§9** AC-09 |
| Single HAProxy entry (`fe_http` / `fe_https`) | **Done** | see **§7.3** |

## §2 Security

| Requirement | Status | Where |
|-------------|--------|-------|
| Rate limit (stick-tables), per-app | **Done** | see **§7.1a** |
| Basic WAF (ACL), per-app | **Done** | see **§7.1a** |
| CrowdSec + decisions (LAPI, decisions in UI) | **Done** | see **§7.5** (ban/unban/whitelist in UI) |
| SPOE bouncer | **Done** | see **§7.3**; template `filter spoe` / `send-spoe-group`; `install.sh`, `docs/CROWDSEC.md` |
| Fail2Ban | **Done** | `GET/POST /api/v1/integrations/fail2ban/*` via **`easy-waf-hostd`** (`fail2ban` opcode); Fail2Ban UI tab; `docs/FAIL2BAN.md`; legacy socket/group path retired |
| GeoIP + cache (ipinfo, batch map, ACL) | **Done** | see **§7.6** |

## §2 UX / Observability

| Requirement | Status | Where |
|-------------|--------|-------|
| Web UI (LAN): 8 tabs, dashboard | **Done** | see **§7.7** |
| Certificates, logs, stats, health | **Done** | see **§7.7**, **§7.8**; audit, `/health`, `/status` |
| Backup/restore | **Done** | **§9** AC-10; `scripts/backup.sh`, `restore.sh`, E2E `scripts/test-backup-restore.sh` |

## §3 Constraints

| Requirement | Status | Where |
|-------------|--------|-------|
| Ubuntu 24.04 LTS, systemd, nftables, AppArmor | **Done** | `scripts/install.sh`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md`, `docs/HOST-API.md` |
| `haproxy -c` before reload | **Done** | see **§7.3**; `internal/apply`, `internal/engine` |
| SPOE, WebSocket, SNI, redirect (golden + CI) | **Done** | see **§7.3** |
| CrowdSec LAPI not via Lua | **Done** | Go LAPI client + SPOA package; see **§7.5**, `docs/CROWDSEC.md` |
| Config generator, validation, atomic apply, rollback | **Done** | see **§7.3**; **§9** AC-06 |
| GeoIP API + batch map + ACL | **Done** | see **§7.6** |
| MaxMind MMDB as provider | **Done** | `geoip_mmdb_path`, `internal/geoip/maxmind.go`, `GET/POST /api/v1/geoip/*`, `docs/GEOIP.md`, `scripts/update-geoip-db.sh` |

## §6 Repository structure (target layout from prompts)

| Path in prompts | In this repo | Notes |
|-----------------|--------------|-------|
| `/internal/config` | `internal/config` | OK |
| `/internal/haproxy` | `internal/haproxy` | Template embedded in `render.go` |
| `/internal/acme` | `internal/acme` | OK |
| `/internal/security` | no separate package | see `profiles`, `api/mgmtacl`, `auth` |
| `/internal/geoip` | `internal/geoip` | OK |
| `/internal/crowdsec` | `internal/crowdsec` | OK |
| `/internal/stats` | `internal/metrics` (HAProxy socket) | see `GET /api/v1/stats/*` |
| `/web/frontend` | `internal/webui/dist` | Embedded via `embed` |
| `/templates/*.tmpl` | inside `render.go` | Can be split to files later |
| `/tests` | focused `*_test.go` + **golden** HAProxy under `internal/haproxy/testdata/golden/` | No separate e2e tree |

## §7 Features

### 7.1 App publishing — **Done** (CRUD API + UI, profiles, restricted paths, health path in model; **HTTP publishing**: per-app `listen_mode`, `fe_http` routing / per-host redirect, migration `012_listen_mode.sql`, golden `http-only-app` / `mixed-listen-modes` / `http-only-reverse-proxy`, audit `app_listen_mode_changed`)

### 7.1a Per-application security — **Done** (migration `009_application_security.sql`, `Application.security`, presets `internal/profiles/modes.go`, HAProxy per-host ACL order, per-app GeoIP maps `geoip_app_*.map`, API `GET/PUT/PATCH /applications/{id}/security`, `POST …/security/mode`, `GET /security/modes`, audit `app_security_mode_changed`, UI cards + Dashboard overview, golden `app-*` / `mixed-apps`, `docs/APPLICATION_SECURITY.md`)

### 7.2 ACME — **Done** (HTTP-01, DNS-01 providers, renew worker, apply hook in `easy-waf-acmed`)

### 7.2a Global settings API — **Done** (`GET /api/v1/settings`; **`PATCH /api/v1/settings`** — partial JSON, merge over current in-memory/DB values; **`PUT /api/v1/settings`** — same merge so a partial body does not zero paths/timeouts; fields `geoip_cache_ttl` and `acme_renewal_interval` in JSON as `time.ParseDuration` strings, e.g. `"24h"`, `"30m"`, plus nanosecond numbers for older snapshots; UI saves ACME via PATCH) — `internal/api/server.go`, `internal/config/settings_merge.go`, `internal/config/duration.go`, `internal/webui/dist/index.html`

### 7.3 HAProxy engine — **Done** (template, checksum, validate, revisions/rollback, golden)

### 7.4 Security profiles — **Done** (names from prompts: `balanced`, `strict`, `trusted-lan`, `public-app`, `home-assistant`) — `internal/profiles/profiles.go`, `docs/SECURITY_PROFILES.md`

### 7.5 CrowdSec — **Done** (ping LAPI, decisions in UI, **Unban** / **Ban IP** / **Allow IP (whitelist)** via LAPI; `cscli` ops outside UI — per docs)

### 7.6 GeoIP — **Done** (`internal/geoip` — ipinfo + **MaxMind GeoLite2-Country.mmdb**, `GET /api/v1/geoip/lookup|stats|providers`, `POST /api/v1/geoip/reload`, settings `geoip_*` / `geoip_mmdb_path`, migrations `007`+`010`, batch `geoip_enforce.map` + ACL in `render.go`, UI section, `docs/GEOIP.md`)

### 7.7 UI pages — **Done** (tabs from §7 prompts + audit/logs, certificate summary)

### 7.8 Statistics — **Done** (`internal/metrics` — HAProxy `show stat` over Unix socket, cache 5s; API `GET /api/v1/stats/haproxy`, `GET /api/v1/stats/summary`; Dashboard traffic + backends, refresh 10s; `haproxy_stats_socket_path` + golden template)

## §8 Lessons learned

Captured in `docs/ARCHITECTURE.md`, `docs/CROWDSEC.md`, `internal/haproxy/render.go` (SNI, ws, validation).

## §9 Acceptance criteria (MVP) — Spec v1.1 (AC-01 … AC-10)

Verified against code and scripts (iterations A–D). **Partial** = depends on environment (NAT, DNS, SPOA package) or deliberately left outside the UI.

| ID | Criterion | Status | Check in repository |
|----|-----------|--------|---------------------|
| **AC-01** | Install via `install.sh` on Ubuntu 24.04 LTS (full cycle: packages, layout, env, optional PostgreSQL, binaries, systemd) | **Done** | `scripts/install.sh` — `apt`, nftables, CrowdSec+SPOA packages, **LAPI bootstrap** (bouncers, `CROWDSEC_LAPI_*`, `-sync-settings-only`), `create_user_and_layout`, `install_env_file`, `systemctl enable --now easy-waf-api.service easy-waf-acmed.service` (`EASY_WAF_ENABLE_SYSTEMD_UNITS`), units `packaging/systemd/*.service`, `WantedBy=multi-user.target` |
| **AC-02** | Add app via UI + Apply | **Done** | UI `#apps` → `POST /api/v1/applications`; `#config` → `POST /api/v1/apply`; `internal/api/server.go`, `internal/engine/engine.go` |
| **AC-03** | HTTPS certificate automatic (ACME) | **Partial** | `cmd/easy-waf-acmed` — issue/renew, on success `eng.Apply(ctx,"acme")`; needs `ACME_EMAIL`, DNS/HTTP-01, worker running (`docs/ACME.md`) |
| **AC-04** | External access to published application | **Partial** | Render `fe_http`/`fe_https`, SNI, Host backends — **Done** in code; WAN/NAT/port-forward routing — outside the repo |
| **AC-05** | CrowdSec blocks; HAProxy returns 403 for denied traffic | **Partial** | Template `filter spoe engine …` + ACL with `deny_status 403` (WAF, IPBL, GeoIP, UA); SPOA decision reaction — bouncer package config + `docs/CROWDSEC.md` |
| **AC-06** | Apply + rollback | **Done** | `engine.Apply` / `Rollback`, DB revisions; `POST /revisions/{id}/rollback`; UI Config (revisions table + button) |
| **AC-07** | UI: apps, certs, blocked | **Done** | Applications, Certificates (incl. summary/actions), Security (IPBL, blocked UA), Dashboard tabs |
| **AC-08** | Survives reboot | **Done** | `systemctl enable` for api/acmed (and optional CrowdSec); `Restart=on-failure` in unit files |
| **AC-09** | WebSocket (e.g. Home Assistant) | **Done** | `timeout tunnel` in defaults and for `websocket` in `internal/haproxy/render.go` |
| **AC-10** | Backup + restore | **Done** | `scripts/backup.sh`, `scripts/restore.sh`, `docs/BACKUP_RESTORE.md`, `scripts/test-backup-restore.sh` |

**AppArmor (from §3 prompts):** Ubuntu uses AppArmor by default; a dedicated easy-waf profile is not required. HAProxy access to configs is via the **`easy-waf`** group. Status: **Done** on Ubuntu 24.04.

## Roadmap (post-MVP)

1. **Release pipeline (basics done):** [`.github/workflows/release.yml`](../.github/workflows/release.yml) — push tag `v*`, `make build`, tarball + `SHA256SUMS`, GitHub Release notes from `CHANGELOG.md`. Next: artifact signing, pre-release/nightly.
2. **MaxMind MMDB (done):** see **`docs/GEOIP.md`**, **`scripts/update-geoip-db.sh`**. Next: MMDB signing, file size/epoch metrics.
3. ~~**CrowdSec in UI**~~ — done (ban/unban/whitelist).
4. ~~**Prometheus `/metrics`**~~ — done (`docs/MONITORING.md`).
5. ~~**Diagnostics bundle**~~ — done (`scripts/diagnostics.sh`, API bundle, `docs/DIAGNOSTICS.md`).
6. **OVA/OVF appliance template** for fast VM deployment.
7. **Smoke test checklist** (manual / semi-automated post-install run).
8. **Tests:** broader e2e / `tests/` tree against compose PostgreSQL.
9. **UI:** optional separate frontend framework instead of a single `index.html`.

Update this file when closing MVP items and when `VERSION` changes.

## Golden tests: **Done**

`Render()` fixtures → snapshots `internal/haproxy/testdata/golden/<scenario>.cfg` + `<scenario>.crt-list.txt`; refresh: `make golden-update` (`UPDATE_GOLDEN=1`). Unit test: `go test ./internal/haproxy/... -run Golden`. Integration `haproxy -c` on golden files: `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (see `render_golden_integration_test.go`).

## CI (GitHub Actions)

| Requirement | Status | Where |
|-------------|--------|-------|
| `go vet`, golangci-lint, `go test -run Golden` (HAProxy golden), `go test -race` (with `-skip TestGoldenRender` to avoid duplicating golden), Linux artifact / LF checks for `scripts/**/*.sh`, `haproxy -c` on generated config + golden (`-tags=integration`) | **Done** | `.github/workflows/ci.yml`, `internal/haproxy/render_golden_test.go`, `internal/haproxy/haproxy_validate_test.go` |
