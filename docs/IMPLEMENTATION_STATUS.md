# Implementation status (Easy Home WAF)

**Last updated:** 2026-11-17

**Current VERSION:** 1.6.1 (see root `VERSION` file)
**Latest full local candidate / VMware delivery:** [6e1fb75](release-evidence/1.6.1-local-gates-6e1fb75.md):
eight Linux gates, 821 race passes, fresh clean govulncheck, both-architecture
release-artifact checks, successful GitHub CI and an actual APT installation on
the independent clone. Strict preserved-state/runtime checks and smoke 19/0/2
passed; fresh restore/reboot and final release approval for this commit remain open.
**Latest PVE dev delivery:** [9cfc841 crypto dependency update](release-evidence/1.6.1-crypto-9cfc841.md),
installed through APT with a new matched backup. All eight local Linux gates,
817 race passes, fresh clean govulncheck and both-arch artifact inspection passed.
Running daemon/payload equality, existing-password authentication, broker RPC,
stats and trusted HTTPS passed on PVE. Release approval remains open.
The public certificate from the [cb2d0a7 production renewal](release-evidence/1.6.1-http01-renewal-cb2d0a7.md)
and the [22ce6f0 reboot](release-evidence/1.6.1-reboot-22ce6f0.md) retain their scopes;
no fresh public renewal or PVE reboot of the new dependency binaries is claimed.
An [actual VMware reboot of 9cfc841](release-evidence/1.6.1-reboot-9cfc841.md)
passed automatic startup of ten units, exact persistent-state/payload checks,
trusted test HTTPS, fresh HAProxy statistics and broker RPC without intervention.
The same package passed a [matched backup and packaged restore on the independent
VMware copy](release-evidence/1.6.1-restore-9cfc841.md), including an actual
maintenance 503 to restored HTTPS 200 transition and exact persisted objects.
Post-restore smoke: 18 passed, 0 failed, 3 skipped; GeoIP lookup returned 502
and remains unverified in that run.
The [GeoIP follow-up](release-evidence/1.6.1-geoip-smoke.md) observed upstream
IPinfo rate limiting and corrected smoke's silent non-200 skip. One live run
with the fixed script passed 19 checks with 0 failures and 2 optional skips.
**Summary.** Capability tables (*Security hardening* … *Platform constraints*): Done — **36**, Partial — **0**, Missing — **0**, N/A — **0**. Acceptance criteria AC-01 … AC-10: Done — **9**, Partial — **1** (AC-03), at the individual scopes below. AC-05 has container and PVE loopback evidence; external-client acceptance remains open. These counts describe coverage, not approval of the current release candidate.

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
| **Login rate limit** | **Done** | Per-IP sliding window **10 attempts / 5 min**, lockout **15 min**; an unparseable client address shares one bucket; `internal/api/ratelimit.go`, `internal/api/auth_handlers.go`, `LoginRL` wired in `internal/bootstrap/run.go` |
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
| Per-application availability diagnosis | **Done** | Applications → **Diagnose**; read-only `GET /applications/{id}/diagnostics` separates DNS, actual TLS material, applied route, HAProxy runtime and backend health, with explicit unknown/not-applicable states |
| Scoped service journal | **Done** | Administrator-only Events & audit panel uses existing `GET /host/journal`; fixed allowlisted services and bounded time/priority/line filters, text-only output |
| High-risk interaction consistency | **Done** | Contextual confirmations for protective-rule and user deletion/reset actions; accessible SSH-key editor; temporary panel passwords use explicit reveal/copy/acknowledge and are cleared when the dialog closes |
| Cross-screen reflow and accessibility | **Done** | All 12 screens verified at 390/768/1440 px and a 200% reflow equivalent; visible form controls have accessible names, mobile navigation restores focus, warnings have semantic toast variants, and sign-in guidance is HTTPS-first |
| Backup/restore | **Done** | **AC-10**; `scripts/backup.sh`, `restore.sh`, E2E `scripts/test-backup-restore.sh`; System explicitly discloses that backup/restore are CLI-only and shows the packaged commands without fake GUI actions |
| Web UI maintainability | **In progress** | `docs/WEBUI_MAINTAINABILITY.md`; deterministic generation and completed Phase 2 screen partials cover every route while preserving byte-identical `dist/index.html`, the single inline script and exact CSP hash; JavaScript separation remains Phase 3 |

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

### 7.2a Global settings API — **Done** (`GET /api/v1/settings`; **`PATCH /api/v1/settings`** — partial JSON, merge over current in-memory/DB values; **`PUT /api/v1/settings`** — disabled (405; `Allow: GET, PATCH`), use PATCH to preserve omitted settings; fields `geoip_cache_ttl` and `acme_renewal_interval` in JSON as `time.ParseDuration` strings, e.g. `"24h"`, `"30m"`, plus nanosecond numbers for older snapshots; UI saves ACME via PATCH) — `internal/api/server.go`, `internal/config/settings_merge.go`, `internal/config/duration.go`, `internal/webui/dist/index.html`

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

The table distinguishes implementation coverage from appliance evidence.
**Done** describes repository coverage at the stated scope, not approval of the
current release candidate. AC-01 has separate scoped clean-install and direct
package-upgrade evidence; AC-08 has scoped PVE/VMware evidence, and AC-05 has
container/PVE loopback evidence. Other candidate checks remain open;
DNS-01 capability is untested.
Actual HTTPS reboot recovery and HTTP-01 failure/backoff passed in the
[PVE follow-up](release-evidence/1.6.1-https-reboot-failure.md).
Public HTTP-01 issuance and renewal, plus independent mobile WAN access, passed
on the [PVE candidate](release-evidence/1.6.1-public-http01.md).
Scoped observations on a real
PVE dev appliance (install/reinstall, smoke, reboot, delayed DB, edge/WebSocket
and CrowdSec; restore follow-up at d33df09) are recorded for [candidate 336b5e0](release-evidence/1.6.1-336b5e0.md).
Those observations alone do not establish pristine installation or all
restored-copy and management-UI checks; later candidate-specific follow-ups are below.
The HAProxy runtime stats socket defect found during browser acceptance was fixed
and checked through actual reloads, Apply, smoke and reboot on
[candidate de84ebb](release-evidence/1.6.1-haproxy-stats.md).
Application creation/manual Apply passed on
[candidate 2220fde](release-evidence/1.6.1-application-apply.md); its favicon and
static guidance follow-ups were repaired and checked in native Edge on
[candidate e48a746](release-evidence/1.6.1-ui-static.md).
The user-reported missing version was repaired and checked in native Edge and
actual CLI binaries on [candidate 6be4467](release-evidence/1.6.1-version.md),
which also has inspected local amd64/arm64 artifacts (no arm64 boot or signatures).
Application deletion controls, profile explanations and Home Assistant route
repairs passed scoped tests and dev-appliance observation on
[candidate d5588ce](release-evidence/1.6.1-application-controls.md). Actual user
publication deletion and end-to-end HA client acceptance were not performed.
Confirmation keyboard handling subsequently passed native Edge acceptance on
[candidate 93eab9f](release-evidence/1.6.1-confirmation-dialog.md).
The published 1.6.0 signature and real-binary PostgreSQL transition from
migrations 019 to 027 passed in an [isolated fixture](release-evidence/1.6.1-release160-migrations.md).
This preparation does not close the actual appliance install/upgrade gate.
An actual signed-1.6.0 baseline, script/tarball transition, preserved HTTPS/data,
smoke and native UI Apply subsequently passed on
[candidate d0eabdf](release-evidence/1.6.1-script-upgrade-d0eabdf.md).
The package was then aligned with APT. A separate direct APT transition from an
actual signed-1.6.0/schema-019 checkpoint subsequently exposed and repaired missing
HAProxy stats recovery; preservation, two API Apply cycles, native UI Apply and
smoke passed on [candidate b5fa4a4](release-evidence/1.6.1-package-upgrade-b5fa4a4.md).
That upgrade reused provisioned OS dependencies. A separate
[pristine VMware installation](release-evidence/1.6.1-pristine-vmware-b5fa4a4.md)
then passed the actual installer on a new authenticated Ubuntu 24.04 cloud image,
fresh enrollment, authenticated smoke, Apply/stats and real reboot on b5fa4a4.
This closes the scoped AC-01 install/upgrade gap; it does not approve all release gates.
The actual backup/factory-reset/restore workflow subsequently passed on an
[independent full VMware copy](release-evidence/1.6.1-restored-copy-b5fa4a4.md),
with preserved data/certificate/env, independent HTTPS, smoke and reboot.
Its restore script came from the exact source archive. A source-independent
operator command was subsequently packaged and passed actual installed-command
recovery on [candidate 677a499](release-evidence/1.6.1-packaged-restore-677a499.md).
Shared backup/restore locking and early archived-env validation subsequently
passed source/extracted/installed regressions and actual recovery on
[candidate 74b0df7](release-evidence/1.6.1-restore-lock-74b0df7.md).
The latest [local candidate follow-up](release-evidence/1.6.1-local-gates-c27c77b.md)
passed all-package Linux race tests with real PostgreSQL, lint/vet/verify,
HAProxy integration, actual isolated nftables rollback and package/CLI checks.
The same c27c77b package is installed on the VMware dev clone with matching
served UI/CSP, preserved baseline state and passing smoke/HTTPS. These are local
equivalents; remote required CI and the remaining appliance/release rows stay open.
The nightly body-policy launcher subsequently had its failed/incomplete-output
false success and Git Bash path conversion repaired; all six result-handling
regressions and the actual 26-case HAProxy/curl suite passed on
[f6bc4ad](release-evidence/1.6.1-body-e2e-f6bc4ad.md). CrowdSec/systemd-APT follow-ups
and remote workflow execution remain separate gates.
The subsequent [CrowdSec/package follow-up](release-evidence/1.6.1-crowdsec-package-f8f7694.md)
passed all five actual LAPI/SPOA network checks and all seven real systemd/APT
lifecycle cases on f8f7694. The installed c27c77b dev clone also recovered from an
actual power cycle with exact baseline data, stats/TLS/smoke and a 2 GiB lab profile;
this is not a production sizing benchmark or a repeat of late-DB failure injection.
The [nightly coverage audit](release-evidence/1.6.1-nightly-audit-c5c322f.md) also
passed the remaining three root-fixture launchers and confirmed actual GitHub CI
success for c27c77b. Runtime/package inputs remain identical through c5c322f;
newer E2E changes, final release notes/signatures and external acceptance remain
separate gates. No release is approved by these aggregate coverage counts.
Named [1.6.1 candidate notes](../CHANGELOG.md#161---unreleased) are now prepared
with an explicit Unreleased status and upgrade/recovery guidance. This closes the
missing-section preparation gap; final acceptance, release date, tag/signatures
and newer remote runs remain open. Notes preparation does not approve publication.
The [PVE candidate alignment](release-evidence/1.6.1-pve-c27-alignment.md)
installed the same verified c27c77b package through APT after a matched private
checkpoint. Exact payload/UI/CSP, unchanged application/certificate objects,
production HTTP-01 served-leaf equality, core services and direct Windows trusted
HTTPS passed. The Windows DNS-address path timed out; fresh external-client and
native-browser acceptance remain open. Existing public certificates were
preserved, not reissued, and no test logout was performed.
The same record confirms successful remote push CI for 8d3da16, including all
three jobs; later notes/evidence commits and a fresh remote nightly E2E run
remain outside that CI scope.
The subsequent [PVE security/WAN follow-up](release-evidence/1.6.1-pve-c27-crowdsec-wan.md)
passed six actual installed CrowdSec baseline/ban/isolation/unban/fail-open/cleanup
checks and received operator-confirmed mobile-data access without TLS warnings
on c27c77b. This supersedes the pending mobile observation above; current-client
forwarded-IP correlation and external-client blocking are not established.
The [native Edge/ACME follow-up](release-evidence/1.6.1-pve-c27-ui-acme.md)
confirmed current version, application/Delete control visibility, valid public
certificate, runtime backend health and rollback guidance after browser reload.
It also found and repaired empty global ACME contact/staging defaults through the
normal API; only those two settings changed, and the worker and trusted HTTPS
remained healthy. Actual renewal and privileged UI mutation flows were not rerun.
Record candidate-specific results using [RELEASE_ACCEPTANCE_TEMPLATE.md](RELEASE_ACCEPTANCE_TEMPLATE.md)
and the procedure in [ACCEPTANCE.md](ACCEPTANCE.md).

| ID | Criterion | Status | Check in repository |
|----|-----------|--------|---------------------|
| **AC-01** | Install via `install.sh` on Ubuntu 24.04 LTS (full cycle: packages, layout, env, optional PostgreSQL, binaries, systemd) | **Done** (scoped VMware/PVE) | Actual default installer, fresh enrollment, authenticated smoke and reboot passed on a [pristine Ubuntu cloud-image VM](release-evidence/1.6.1-pristine-vmware-b5fa4a4.md); direct signed-1.6.0/schema-019 APT transition passed separately on [PVE](release-evidence/1.6.1-package-upgrade-b5fa4a4.md). Both use local b5fa4a4 candidate artifacts; final signed-release acceptance remains open. Implementation: `scripts/install.sh` — `apt`, nftables, CrowdSec+SPOA packages, **LAPI bootstrap**, local PostgreSQL, layout/env/binaries and packaged systemd units. Follow [ACCEPTANCE.md](ACCEPTANCE.md). |
| **AC-02** | Add app via UI + Apply | **Done** (scoped PVE) | Native Edge form creation and Config → Apply HAProxy passed on [candidate 2220fde](release-evidence/1.6.1-application-apply.md), with an independent backend HTTP 200 marker before and after manual Apply and cleanup of the owned test application. Implementation: `#apps` → `POST /api/v1/applications`; `#config` → `POST /api/v1/apply`; `internal/api/server.go`, `internal/engine/engine.go` |
| **AC-03** | HTTPS certificate automatic (ACME) | **Partial** | `cmd/easy-waf-acmed` — issue/renew, on success transactional publication and `ApplyIfChanged`; needs global `acme_email`, DNS/HTTP-01, worker running (`docs/ACME.md`). Production HTTP-01 and renewal with trusted served TLS passed on the [PVE candidate](release-evidence/1.6.1-public-http01.md); a real NXDOMAIN HTTP-01 failure/backoff passed in the [follow-up](release-evidence/1.6.1-https-reboot-failure.md). Fresh production HTTP-01 renewal after the global configuration repair passed on [cb2d0a7](release-evidence/1.6.1-http01-renewal-cb2d0a7.md), including new DB/served leaf, trusted Windows request and native UI expiry. DNS-01 and optional notification checks remain scoped by [ACCEPTANCE.md](ACCEPTANCE.md) |
| **AC-04** | External access to published application | **Done** (scoped PVE) | Operator-confirmed mobile-data HTTPS request without certificate warnings, with the external client IP matched between HAProxy and backend X-Forwarded-For on the [PVE candidate](release-evidence/1.6.1-public-http01.md). WAN/NAT routing remains deployment-specific; follow [ACCEPTANCE.md](ACCEPTANCE.md). |
| **AC-05** | CrowdSec blocks; HAProxy returns 403 for denied traffic | **Done** (containers; scoped PVE) | The generated config sends each request to the bouncer and returns 403 for any remediation other than `allow` (`internal/haproxy/render.go`, `docs/CROWDSEC.md`); fails open. Proven against a real LAPI and bouncer by `scripts/test-crowdsec-e2e.sh`, nightly in `.github/workflows/e2e.yml`; a real dev appliance also passed ban/unban/fail-open with a dedicated loopback client ([candidate evidence](release-evidence/1.6.1-336b5e0.md)); external-client acceptance remains scoped by [ACCEPTANCE.md](ACCEPTANCE.md) |
| **AC-06** | Apply + rollback | **Done** (scoped VMware) | Actual HAProxy validation rejection preserved live files, worker/master, revisions and HTTPS; maintenance Apply returned 503 and revision rollback restored 200 on [candidate 74b0df7](release-evidence/1.6.1-apply-rollback-74b0df7.md). Revision rollback restores artifacts, not application rows; cleanup realigned DB/edge and restored the matched checkpoint. Implementation: `engine.Apply` / `Rollback`, DB revisions; `POST /revisions/{id}/rollback`; UI Config (revisions table + button). |
| **AC-07** | UI: apps, certs, blocked | **Done** (scoped PVE views) | Authenticated native Edge views on [candidate e95ccb3](release-evidence/1.6.1-ui-csp.md) matched API application inventory, certificate validity and blocked-request count. Application creation/Apply subsequently passed on [candidate 2220fde](release-evidence/1.6.1-application-apply.md); other UI workflows remain separate checks. |
| **AC-08** | Survives reboot | **Done** (scoped PVE/VMware) | Actual reboot with trusted published-HTTPS recovery passed in the [PVE follow-up](release-evidence/1.6.1-https-reboot-failure.md); late-PostgreSQL startup recovery passed on the same binary [candidate](release-evidence/1.6.1-336b5e0.md). An actual c27c77b VMware power cycle also preserved data/certs and recovered TLS/stats/smoke on the [2 GiB lab profile](release-evidence/1.6.1-crowdsec-package-f8f7694.md). A fresh actual PVE reboot passed on [22ce6f0](release-evidence/1.6.1-reboot-22ce6f0.md) after an owned backend fixture correction, with trusted HTTPS, exact data/payload, runtime stats and Windows verification; this did not repeat late-DB injection. Implementation: `systemctl enable` for hostd/api/acmed (and optional CrowdSec); `Restart=on-failure` in unit files; api/acmed use `RestartSec=5` and `StartLimitIntervalSec=0`, so they keep retrying until a late PostgreSQL is up |
| **AC-09** | WebSocket (e.g. Home Assistant) | **Done** (scoped transport) | Real HAProxy 101 Upgrade, masked-frame echo beyond shortened HTTP idle limits and MCP-only denial passed with race detection on [candidate 580f5df](release-evidence/1.6.1-websocket-580f5df.md). Installed-appliance [WSS on 677a499](release-evidence/1.6.1-wss-reload-677a499.md) survived 62s silence and actual API Apply/reload on the same connection, with independent TLS/stats/cleanup checks. Direct HA handshake reached `auth_required`; authenticated HA/Companion acceptance and proxy trust for the new NAT test path remain open. Implementation: `timeout tunnel` in defaults and for `websocket` in `internal/haproxy/render.go`. |
| **AC-10** | Backup + restore | **Done** (scoped VMware copy) | Actual backup/factory-reset/restore E2E, independent data/certificate/env/TLS/stats checks, authenticated smoke and reboot passed on [candidate b5fa4a4](release-evidence/1.6.1-restored-copy-b5fa4a4.md). The installed `easy-waf-restore` command subsequently passed recovery without the expected source checkout, negative controls, TLS/stats/permissions and smoke on [candidate 677a499](release-evidence/1.6.1-packaged-restore-677a499.md). Shared-lock/preflight regressions and actual installed recovery passed on [candidate 74b0df7](release-evidence/1.6.1-restore-lock-74b0df7.md). Same-version amd64 scope. Implementation: `scripts/backup.sh`, `scripts/restore.sh`, `docs/BACKUP_RESTORE.md`, `scripts/test-backup-restore.sh`. |

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
10. **OpenClaw publication template — planned:** requested for homelab and smart-home deployments. Before implementation, verify upstream deployment guidance, authentication and trusted-proxy requirements, WebSocket/streaming behavior, and whether UI, API or MCP endpoints need separate policies. Provide clear template help, a deployment example and real HAProxy integration coverage; do not assume the Home Assistant profile is suitable. This is a backlog item, not an implemented profile or an additional 1.6.1 release gate.

Update this file when closing MVP items and when `VERSION` changes.

## Golden tests: **Done**

`Render()` fixtures → snapshots `internal/haproxy/testdata/golden/<scenario>.cfg` + `<scenario>.crt-list.txt`; refresh: `make golden-update` (`UPDATE_GOLDEN=1`). Unit test: `go test ./internal/haproxy/... -run Golden`. Integration `haproxy -c` on golden files: `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (see `render_golden_integration_test.go`).

## CI (GitHub Actions)

| Requirement | Status | Where |
|-------------|--------|-------|
| `go vet`, golangci-lint, `go test -run Golden` (HAProxy golden), `go test -race` (with `-skip TestGoldenRender` to avoid duplicating golden), Linux artifact / LF checks for `scripts/**/*.sh`, `haproxy -c` on generated config + golden (`-tags=integration`), store/engine/auth integration tests against a PostgreSQL 16 service container | **Done** | `.github/workflows/ci.yml`, `internal/haproxy/render_golden_test.go`, `internal/haproxy/haproxy_validate_test.go` |
| Container end-to-end: the body policy and CrowdSec decisions against HAProxy 2.8 with a real LAPI and bouncer | **Done** | [`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml), nightly and on demand; `scripts/test-body-policy-e2e.sh`, `scripts/test-crowdsec-e2e.sh` |
