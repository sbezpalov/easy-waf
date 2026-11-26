# Implementation status (Easy Home WAF)

**Last updated:** 2026-11-26

**Current VERSION:** 1.6.1 (see root `VERSION` file)

**Next appliance platform.** The migration target is Ubuntu Server 26.04.1
LTS (Resolute) with HAProxy 3.4 LTS. The `haproxy-34` CI job validates
rendered configurations and live routing on amd64 and arm64 using the
packaging maintainer's signed PPA. Ubuntu 24.04 remains the supported base
for 1.6.1. On a clean Ubuntu Server 26.04.1 LTS amd64 VMware guest,
the installer helpers at `9a11866` installed CrowdSec 1.8.2 and its
HAProxy SPOA bouncer 0.4.0. Both services ran under systemd. With the
HTTP-only application fixture on HAProxy 3.4.8, one client received 200
before a CrowdSec ban, 403 during the ban and 200 after deletion. A second
client received 200 during the ban.

**26.04.1 offline installation (amd64, 2026-11-26).** The builder and
installer at `1f25823` passed a full-profile installation on a fresh VMware
disk cloned from the Ubuntu Server cloud image. The guest had no network
adapter. Only loopback was up, with no external IPv4 or IPv6 route on either
boot. The read-only ISO contained 187 packages including Easy WAF 1.6.1
(ISO SHA-256 `c9eb89ea9160bce32478e7699398af90f3b9c87c406f446a08399a3cd37121dc`).
The installer rejected a missing CrowdSec snapshot before provisioning and
succeeded with a verified snapshot on a second read-only medium. System
APT sources and indexes retained their original hashes.

After a reboot with a different boot ID, the API, ACME worker, host broker,
HAProxy, PostgreSQL, nftables, Fail2Ban, CrowdSec, SPOA bouncer and backup
timer were active. HAProxy 3.4 passed configuration validation, PostgreSQL
contained migration 031, CrowdSec LAPI accepted the local agent, and the
management HTTPS readiness check passed using the appliance certificate.

**26.04.1 backup and restore (amd64, 2026-11-26).** A network-isolated
clone of that installation passed recovery using the packaged
`easy-waf-backup` and `easy-waf-restore` commands. The backup had mode
`0600`, and the API and ACME worker resumed after capture. After changing
a database setting, a state file and a configuration file, restoring the
archive recovered all three original values. The configuration directory
and environment files had their expected owners and permissions. Edge
configuration applied successfully, the appliance services and backup timer
were active, and HTTPS readiness passed with certificate verification.

**26.04.1 offline APT upgrade (amd64, 2026-11-26).** On a separate
network-isolated clone with the 26.04.1 dependencies already installed,
the published 1.6.0 package initialized a fresh PostgreSQL database through
migration 019 and served the HTTPS readiness endpoint. APT upgraded it to
the local 1.6.1 candidate from read-only media (DEB SHA-256
`b12cfed5e8b93b9c23b31e7602986502e1da4a06968d29603ad53c9943faf898`).
All 31 migrations were recorded. A database setting survived the upgrade,
and the management certificate and environment file retained their hashes.
The API, ACME worker and host broker processes ran binaries matching the
candidate DEB. HAProxy configuration and trusted HTTPS readiness passed.
This covers the application package upgrade within 26.04.1. Cross-release
OS migration and release-image boot checks are separate acceptance items.

**26.04 offline media (arm64, 2026-11-26).** The local build from
`72ca259` resolved the full profile from the Ubuntu, HAProxy 3.4 and
CrowdSec repositories for arm64. The ISO indexed 187 packages and passed
the isolated APT dependency check. After extraction, `install.sh --verify-only`
verified the manifest, and both embedded copies of the DEB matched the
independently retained package byte for byte.

| Local candidate | SHA-256 |
| --- | --- |
| Ubuntu 26.04 arm64 offline ISO | `4fe5b493d8685209221c3e8f6e2d1da7abf6db70c8015c19a4c78afe82026ee8` |
| Easy WAF 1.6.1 arm64 DEB | `64596264badeb075a9ecf770fda1ac0082f59287940b4cee24b8cebd8342bdf0` |

The full profile installed on a fresh Ubuntu Server 26.04.1 arm64 cloud
disk under QEMU 8.2.2 with no network adapter. The installer rejected a
missing CrowdSec snapshot before provisioning, then completed with a verified
snapshot mounted read-only. The system APT sources and indexes retained
their original hashes. Installation took approximately 38 minutes under
software emulation after the missing-snapshot check. An earlier run reached
the test harness's 30-minute installation timeout.

The in-guest reboot reached a new boot ID, then systemd timed out waiting
for the `BOOT` and `UEFI` partitions. QEMU's image check passed on the
stopped disk. A separate cold boot of that same disk with an emulated
Cortex-A72 reached a new boot ID with only loopback. The appliance service
checks, HAProxy 3.4 configuration validation, PostgreSQL migration 031,
CrowdSec LAPI and management HTTPS readiness with certificate verification
all passed. In a follow-up on the same installed disk with the Cortex-A72
configuration, `systemctl reboot` produced a new boot ID. Ubuntu mounted
`/boot` and `/boot/efi` on both boots. The same appliance checks passed
after the reboot, and the guest powered down cleanly. The initial failure
occurred with QEMU's `max` CPU model.

**Published 1.6.1 acceptance:** [b6b6721](release-evidence/1.6.1-release-acceptance.md).
After the upgrade with the published package, mobile data access passed with
external HTTPS 200, two WebSocket 101 responses and zero HTTP 429 responses
during the Companion check.

**GeoIP archive budget:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md).
Both architectures' packages and ISOs passed local build and payload checks.
The PostgreSQL-backed race suite passed 924 tests with four skips. Live
HAProxy and the separate root checks passed. The installed [amd64](release-evidence/1.6.1-local-gates-a457e58.md#amd64-offline-appliance-and-geoip-upload)
and [arm64](release-evidence/1.6.1-local-gates-a457e58.md#arm64-offline-appliance-and-geoip-upload)
APIs accepted the synthetic archive and preserved the exact MMDB bytes.

**Rollback status fix candidate:** [6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md).
Native Linux build checks and independent Windows hash and payload checks
passed for both architectures. The broker, API and panel regression tests
passed. The PostgreSQL-backed race suite passed 923 tests with four skips,
and the live HAProxy and root checks passed. Both corrected ISOs passed local
appliance acceptance.

**Current same-version amd64 reinstall:** [707f279 to 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#same-version-amd64-package-reinstall).
An isolated VMware clone retained schema 029, settings, management TLS and
HAProxy configuration. The three restarted daemons ran the exact new binaries.

**Windows developer verification:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#geoip-archive-regression-and-linux-race)
passed the full Go test command and golangci-lint on Windows amd64 with Go
1.27.4. The [707f279 run](release-evidence/1.6.1-local-gates-707f279.md#windows-developer-checks)
also recorded `go vet`.

**Current local packages:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#build-and-payload-checks).
A disconnected Ubuntu VMware guest passed `make verify` and the native Go
suite, then built and verified both DEBs and tarballs. The packaged backup
and restore scripts match the source. Windows independently verified the
package hashes and the embedded source revision in both tarballs.

**Current local offline ISOs:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#build-and-payload-checks).
Both images passed the isolated APT solve and full bundle verification. The
verified DEBs include the rollback status polling fix and GeoIP archive budget.

**Current amd64 offline installation:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#amd64-offline-appliance-and-geoip-upload).
A disconnected Ubuntu VMware guest passed clean installation under `umask
077`, reboot, API time zone and journal checks, nftables confirmation and
rollback, both Zabbix service and package inventory cases, repeat installation
without the snapshot and backup and restore. The installed pending status API
also passed both contention cases. The [6fe3be2 run](release-evidence/1.6.1-local-gates-6fe3be2.md#amd64-offline-appliance-installation)
records the previous candidate.

**Current Apply and WebSocket checks:** [6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#installed-apply-rollback-and-websocket)
passed on two fresh VMware guests. HAProxy validation rejection
preserved live HTTPS, and revision rollback recovered HTTPS from maintenance.
A separate WSS connection survived worker replacement and 62 seconds idle.

**Earlier amd64 installer failure and recovery:** [3463cfd](release-evidence/1.6.1-firewall-directory-3463cfd.md#installed-firewall-access-and-time-zone).
An intermittent CrowdSec startup crash left the verified snapshot receipt in
place. The updated bootstrap retry recovered the original snapshot on an
isolated clone after one injected restart failure.

**Current arm64 offline installation:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#arm64-offline-appliance-and-geoip-upload).
A disconnected Ubuntu 24.04.5 QEMU guest with a clock behind the bundle's APT
metadata passed installation, reboot, authenticated About and repeat installation
without the snapshot. The installed API passed time zone, rollback status under
contention, nftables confirmation and automatic rollback, Zabbix inventory,
and a GeoIP archive upload that preserved the exact MMDB bytes.
The [707f279 ARM64 run](release-evidence/1.6.1-local-gates-707f279.md#arm64-offline-installation-and-firewall-status-failure)
records the HTTP 500 that led to the fix.

**Current PostgreSQL recovery and reboot:** [6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#postgresql-recovery-and-published-https-across-reboot).
An installed VMware guest continued serving trusted HTTPS while PostgreSQL
was down. API and ACME recovered automatically, and the same route and
certificate survived a reboot.

**Current direct amd64 upgrade:** [1.6.0 to 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#amd64-upgrades-from-160).
Offline APT migrated schema 019 to 029, preserved a database marker and
management files, and brought the new binaries to trusted HTTPS readiness.

**Current unpackaged amd64 upgrade:** [1.6.0 to 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#amd64-upgrades-from-160).
The verified tarball and exact upgrade wrapper restarted the three daemons,
migrated schema 019 to 029 and preserved the synthetic publication and its TLS
certificate. An authenticated API Apply returned the same trusted HTTPS
response with an active backend and matching saved and applied generations.

**Signed release verification:** [published 1.6.1 assets](release-evidence/1.6.1-release-acceptance.md).
All 12 files matched their GitHub SHA-256 digests. Cosign verified the package
manifest and both ISOs. The [earlier 1.6.0 replay](release-evidence/1.6.1-packages-9f2f493.md#signed-release-verification)
covered downloader acceptance and rejection of tampered assets.

**Current local publication preflight:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#local-publication-preflight-and-hosted-checks).
The release notes include the GeoIP fix. The publication script verified both
real ISOs and the complete local asset set, and rejected a signature failure
and a mismatched arm64 ISO before the recorded publication call.

**Earlier offline ISO installation acceptance:** [72cbd62](release-evidence/1.6.1-release-provenance-72cbd62.md).
Both architectures passed package build, embedded source-revision verification,
offline APT dependency resolution and exact ISO payload comparison.
Both ISOs passed installation, reboot, live About verification and repeat
installation without a network adapter. The amd64 guest used VMware, and
the arm64 guest used QEMU system emulation.

**Earlier offline installation evidence:** [1faf1fe](release-evidence/1.6.1-current-artifacts-1faf1fe.md).
The DEBs, tarballs and public offline ISOs for amd64 and arm64 passed local
checksums and payload comparison with the updated HAProxy renderer.
Linux verification of this commit passed lint, the PostgreSQL-backed race
suite, the CI HAProxy integration selection and `make verify`.
The local nightly fixtures also passed, including the systemd/APT lifecycle,
PostgreSQL archive SCRAM and real nftables rollback.
Both ISOs passed a clean full-profile install, reboot and repeat install
without a network adapter, using VMware for amd64 and QEMU system
emulation for arm64.

**Earlier pre-tag verification:** [e066d3f](release-evidence/1.6.1-pre-tag-e066d3f.md).
Both DEBs, tarballs and offline ISOs built and passed verification. The
full Linux suite, live HAProxy tests and all six local E2E launchers passed
at the scopes in the report. Remote CI for the release commit, release
approval and validation of the signed assets remain open. DNS-01 is deferred.

**Earlier local Linux runtime checks:** [e02aebb](release-evidence/1.6.1-runtime-gates-e02aebb.md#ubuntu-runtime-checks).
The PostgreSQL-backed suite passed 893 top-level tests, and all five live
HAProxy integration checks passed. This run used `CGO_ENABLED=0`.

**Current local Linux race:** [a457e58](release-evidence/1.6.1-local-gates-a457e58.md#geoip-archive-regression-and-linux-race).
The PostgreSQL-backed race suite passed 924 top-level tests with four skips.
The separate golden, live HAProxy and root checks passed. An [earlier run and
standalone diagnostic](release-evidence/1.6.1-runtime-gates-e02aebb.md#linux-race-checks)
reproduced an intermittent Go 1.27.4 race warning in a sequential APT log test.

**Current hosted CI:** [5eda6d7](release-evidence/1.6.1-local-gates-6fe3be2.md#hosted-ci).
The main push workflow passed `verify`, `lint-and-test` and
`haproxy-config-test` with the `6fe3be2` candidate code.

**Current installed CrowdSec:** [6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#installed-crowdsec-enforcement-and-recovery).
The isolated appliance passed selective blocking, unban, fail-open while the
bouncer was stopped, enforcement after restart and cleanup.

**Current Docker edge E2E:** [6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#local-e2e-workflow-checks).
The local HAProxy body policy and CrowdSec scenarios passed all 31 cases,
including selective blocking and fail-open. The scheduled GitHub E2E passed on
the earlier `e34b562` revision.

**Earlier Docker installer and backup launchers:** [707f279](release-evidence/1.6.1-local-gates-707f279.md#local-docker-installer-and-backup-e2e).
The installer conffile, HAProxy working directory, backup and restore launchers
passed with a pinned Ubuntu 24.04 amd64 base.

**Current systemd/APT and native E2E:** [6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#local-e2e-workflow-checks).
The isolated Docker package lifecycle fixture passed all seven cases.
An isolated VMware fixture passed the installer conffile, HAProxy working
directory, backup publication, restore permissions, archive locking and
PostgreSQL SCRAM checks. A private network namespace passed both native
nftables checks, including closing the managed Zabbix port and rollback.
The [earlier e02aebb checks](release-evidence/1.6.1-runtime-gates-e02aebb.md#native-end-to-end-checks)
also record results on that revision.

**Earlier Linux race coverage:** [41debb4](release-evidence/1.6.1-runtime-gates-41debb4.md).
The race suite with PostgreSQL, the separate root cases and the CI HAProxy
integration selection passed. The [earlier 85d8332 run](release-evidence/1.6.1-local-gates-85d8332.md)
also covered lint, repository verification and amd64/arm64 DEB payloads.
The [offline ISO follow-up on 77d73e0](release-evidence/1.6.1-offline-iso-77d73e0.md)
passed both isolated APT solves, checksum validation and comparison with the
exact amd64 and arm64 candidate DEBs.

The [amd64 offline follow-up on 441e499](release-evidence/1.6.1-offline-vmware-441e499.md)
verified clean installation of that candidate's public-profile ISO with a separate
CrowdSec snapshot, isolated APT state, appliance readiness after reboot and
repeat installation without the snapshot on a VMware guest with no network
adapter.
The [arm64 follow-up on the same commit](release-evidence/1.6.1-offline-arm64-441e499.md)
verified the offline build, clean installation, restart and repeat
installation without the snapshot in an isolated QEMU guest.

The [local release archives on 441e499](release-evidence/1.6.1-release-assets-441e499.md)
passed the workflow build step, checksum verification and binary comparison
between the tarball and DEB for each architecture.

**Offline ISO:** [amd64 VMware and ARM64 QEMU acceptance](release-evidence/1.6.1-offline-iso-3ef58b7.md).
The amd64 ISO passed its dependency solve and both manifests. Offline APT
configured Easy WAF on a clean guest. The full profile then stopped in
CrowdSec 1.8.2's online Hub refresh during dpkg configuration. A manual
local Hub snapshot enabled the default collections and let the same ISO
complete installation with the network down. The opt-in private amd64
ISO from `cb5f8c1` passed clean VMware installation with no network
adapter, automatic activation of the snapshot, and reinstallation with
existing CrowdSec configuration. The public-profile amd64 ISO from
`66f30ea` also passed installation with a separately transferred snapshot
and reinstallation after that snapshot was unmounted. The public-profile
ARM64 ISO from `9a7c2f9` passed the same two checks on a clean Ubuntu
24.04.5 QEMU guest with no network adapter.

**Latest local Linux verification:** [39742bd](release-evidence/1.6.1-linux-gates-39742bd.md).
The full race suite with PostgreSQL, live HAProxy integration, fresh
govulncheck and repository verification passed. The local nightly scenarios
also passed across Docker and VMware, including systemd/APT lifecycle, real
nftables rollback and PostgreSQL archive SCRAM. The GitHub CI and nightly
runs cover the earlier commits named in the report.

**Latest local artifact and packaged recovery:** [3f039d9 on VMware](release-evidence/1.6.1-reinstall-backup-3f039d9.md).
Both architectures passed artifact verification. The amd64 package passed a
same-version APT reinstall, packaged backup and restore, authenticated smoke
and an independent Windows publication check.

**Latest pristine VMware installation:** [4f64bc4](release-evidence/1.6.1-pristine-vmware-4f64bc4.md).
The default amd64 installer, fresh CrowdSec setup, enrollment and schema 028
passed. The backup timer started on the first installation. Both smoke runs
passed 20/0/2 and the publication recovered before any post-reboot Apply.
**Latest unpackaged upgrade:** [published 1.6.0 through upgrade.sh on VMware](release-evidence/1.6.1-source-upgrade-7a1499b.md).
The wrapper returned 0, restarted all three daemons and migrated schema 019 to
028. The publication retained its certificate and trusted HTTPS. HAProxy stats,
API Apply and authenticated smoke passed. The installer reran CrowdSec bootstrap.
**Latest direct APT upgrade:** [published 1.6.0 to bccbf26 on VMware](release-evidence/1.6.1-upgrade-160-bccbf26.md).
The migration ledger advanced from 019 to 028. The existing HTTPS publication,
certificate and HAProxy statistics passed after upgrade. The clone's prior state
was verified after restore. The run exercised APT directly.
**Latest VMware package and backup:** [2bdeca3](release-evidence/1.6.1-backup-2bdeca3.md).
The installed backup preserved the previous archive on stop refusal. It retained
a usable private archive on restart refusal, and packaged restore verified it.
The [timer-driven run](release-evidence/1.6.1-scheduled-backup-9d7dbc8.md) on a
separate VMware guest produced a private archive and resumed both writers. A
subsequent restore of that archive recovered the original HTTP publication,
configuration and schema 028.
**Latest VMware package and restore:** [d5f7475](release-evidence/1.6.1-restore-d5f7475.md).
The installed command rejected a real systemd stop refusal before database work,
reported incomplete recovery when Apply was unavailable, and restored trusted
HTTPS after a verified maintenance 503.
**Latest local appliance E2E:** [218b833](release-evidence/1.6.1-appliance-e2e-218b833.md).
Six scenarios passed, covering installer conffiles, HAProxy working directory,
backup/restore, systemd/APT, nftables rollback and CrowdSec.
**Latest full native Linux race:** [24bfc42 on Ubuntu VMware](release-evidence/1.6.1-native-linux-race-24bfc42.md).
858 tests passed in 49 packages with PostgreSQL 16. The separate golden gate also
passed. The earlier [8c860d3 WSL2 run](release-evidence/1.6.1-linux-race-8c860d3.md)
still records one PBKDF2 report and seven passing gates. The earlier Scanner/UTF-8
pattern recurred in a standalone program in WSL2. Its binary passed on VMware.
**Latest VMware boot recovery:** [2b025f6, schema 028](release-evidence/1.6.1-edge-generation-reboot.md).
The corrected settings upsert preserved the applied generation and HAProxy
revision over an actual boot. All ten checked services recovered automatically.
The same clone also passed a matched rollback to schema 027 in an empty database
and a verified return to the fixed schema 028 package.
**Latest VMware delivery:** [ecadad2, schema 028](release-evidence/1.6.1-vmware-schema-028.md).
The upgraded UI bundle, CSP, reconciled edge status and smoke passed on the clone.
A same-version restore on the clone recovered the original edge generation,
persisted state and HTTPS 200 after a verified maintenance 503.
GitHub CI passed for the runtime source commit `e7b2fad`. The local full race
run reported two failures that did not recur in focused tests. Their cause
remains open.
**Latest full local candidate / VMware delivery:** [6e1fb75](release-evidence/1.6.1-local-gates-6e1fb75.md):
eight Linux gates, 821 race passes, fresh clean govulncheck, both-architecture
release-artifact checks, successful GitHub CI and an actual APT installation on
the independent clone. Strict preserved-state/runtime checks and smoke 19/0/2
passed; fresh restore/reboot and final release approval for this commit remain open.
**Latest PVE dev delivery:** [dd27d74 UI and appliance package](release-evidence/1.6.1-pve-gui-dd27d74.md).
The installed and running executables matched the verified package, the
served UI and CSP matched the current assets, and schema 028, ten active
services or timers, preserved application/certificate/settings state, and
trusted HTTPS passed.

**Earlier PVE delivery:** The [9cfc841 crypto dependency update](release-evidence/1.6.1-crypto-9cfc841.md) was
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
**Summary.** Capability tables (*Security hardening* … *Platform constraints*): Done — **36**, Partial — **0**, Missing — **0**, N/A — **0**. Acceptance criteria AC-01 … AC-10: Done — **9**, Partial — **1** (AC-03), at the individual scopes below. AC-05 includes [external mobile-client acceptance on PVE](release-evidence/1.6.1-pve-ac05-mobile.md). These counts describe coverage, not approval of the current release candidate.

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
| Web UI maintainability | **In progress** | `docs/WEBUI_MAINTAINABILITY.md`; deterministic generation and completed Phase 2 screen partials cover every route; Phase 3b begins responsibility-based JavaScript separation with shared leaf renderers while preserving byte-identical `dist/index.html`, one inline script and the exact CSP hash |

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
PVE mobile-client, loopback and container evidence. Other candidate checks remain open;
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
on c27c77b. That run left external-client blocking and forwarded-IP correlation
open. A [later PVE mobile-data test](release-evidence/1.6.1-pve-ac05-mobile.md)
confirmed CrowdSec blocking and recovery by matching the same public client in
the HAProxy journal.
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
| **AC-01** | Install via `install.sh` on Ubuntu 24.04 LTS (full cycle: packages, layout, env, optional PostgreSQL, binaries, systemd) | **Done** (scoped VMware/PVE) | The [installed 6fe3be2 offline ISO](release-evidence/1.6.1-local-gates-6fe3be2.md#amd64-offline-appliance-installation) passed clean installation, reboot and smoke on amd64. Both [upgrade paths from 1.6.0](release-evidence/1.6.1-local-gates-6fe3be2.md#amd64-upgrades-from-160) passed. The [pristine VMware run](release-evidence/1.6.1-pristine-vmware-4f64bc4.md) passed default installation, CrowdSec bootstrap, enrollment, schema 028, immediate backup scheduling, authenticated smoke and reboot on 4f64bc4. VMware also passed direct upgrades from published 1.6.0/schema 019 [through APT](release-evidence/1.6.1-upgrade-160-bccbf26.md) and [through the unpackaged installer](release-evidence/1.6.1-source-upgrade-7a1499b.md). A separate [earlier PVE package upgrade](release-evidence/1.6.1-package-upgrade-b5fa4a4.md) passed. The [published 1.6.1 package](release-evidence/1.6.1-release-acceptance.md#mobile-acceptance-after-upgrade) passed the same-version APT upgrade and management readiness check. See [ACCEPTANCE.md](ACCEPTANCE.md). |
| **AC-02** | Add app via UI + Apply | **Done** (scoped PVE and VMware) | Native Edge form creation and Config → Apply HAProxy passed on [PVE candidate 2220fde](release-evidence/1.6.1-application-apply.md), with an independent backend HTTP 200 marker before and after manual Apply and cleanup of the owned test application. [VMware candidate 79d7f16](release-evidence/1.6.1-browser-apply-79d7f16.md) passed browser Cancel and Confirm against the installed package, with a new active revision and an independent HTTP check. Implementation: `#apps` → `POST /api/v1/applications`; `#config` → `POST /api/v1/apply`; `internal/api/server.go`, `internal/engine/engine.go` |
| **AC-03** | HTTPS certificate automatic (ACME) | **Partial** | `cmd/easy-waf-acmed` — issue/renew, on success transactional publication and `ApplyIfChanged`; needs global `acme_email`, DNS/HTTP-01, worker running (`docs/ACME.md`). Production HTTP-01 and renewal with trusted served TLS passed on the [PVE candidate](release-evidence/1.6.1-public-http01.md); a real NXDOMAIN HTTP-01 failure/backoff passed in the [follow-up](release-evidence/1.6.1-https-reboot-failure.md). Fresh production HTTP-01 renewal after the global configuration repair passed on [cb2d0a7](release-evidence/1.6.1-http01-renewal-cb2d0a7.md), including new DB/served leaf, trusted Windows request and native UI expiry. DNS-01 and optional notification checks remain scoped by [ACCEPTANCE.md](ACCEPTANCE.md) |
| **AC-04** | External access to published application | **Done** (scoped PVE) | The [published 1.6.1 package](release-evidence/1.6.1-release-acceptance.md#mobile-acceptance-after-upgrade) served Home Assistant over mobile data without a certificate warning and HAProxy logged HTTPS 200. The [earlier PVE check](release-evidence/1.6.1-public-http01.md) matched the external client address between HAProxy and backend X-Forwarded-For. WAN/NAT routing remains deployment-specific. See [ACCEPTANCE.md](ACCEPTANCE.md). |
| **AC-05** | CrowdSec blocks; HAProxy returns 403 for denied traffic | **Done** (scoped VMware and PVE) | [Installed 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#installed-crowdsec-enforcement-and-recovery) passed selective ban/unban, fail-open with an active LAPI decision and enforcement after bouncer restart on a disconnected VM. The [mobile-data PVE run](release-evidence/1.6.1-pve-ac05-mobile.md) correlated HTTPS 200 → CrowdSec 403 → 200 to one public client and verified decision cleanup. The nightly `scripts/test-crowdsec-e2e.sh` covers a real LAPI and bouncer in containers. |
| **AC-06** | Apply + rollback | **Done** (scoped VMware) | On [installed 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#installed-apply-rollback-and-websocket), HAProxy rejection preserved live files, worker/master, revisions and trusted HTTPS. Maintenance returned 503, then revision rollback restored 200 and the target config hash. Cleanup aligned the saved application with the restored edge. The [earlier 74b0df7 run](release-evidence/1.6.1-apply-rollback-74b0df7.md) also restored a matched checkpoint. Implementation: `engine.Apply` / `Rollback`, DB revisions; `POST /revisions/{id}/rollback`; UI Config (revisions table + button). |
| **AC-07** | UI: apps, certs, blocked | **Done** (scoped PVE views) | Authenticated native Edge views on [candidate e95ccb3](release-evidence/1.6.1-ui-csp.md) matched API application inventory, certificate validity and blocked-request count. Application creation/Apply subsequently passed on [candidate 2220fde](release-evidence/1.6.1-application-apply.md); other UI workflows remain separate checks. |
| **AC-08** | Survives reboot | **Done** (scoped PVE/VMware) | [Installed 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#postgresql-recovery-and-published-https-across-reboot) kept published HTTPS available with PostgreSQL down, recovered API and ACME automatically, and preserved the route and certificate across a reboot. Earlier [PVE reboot evidence](release-evidence/1.6.1-reboot-22ce6f0.md) includes independent Windows verification, and the [2 GiB VMware profile](release-evidence/1.6.1-crowdsec-package-f8f7694.md) recovered after a power cycle. API and ACME use `Restart=on-failure`, `RestartSec=5`, and `StartLimitIntervalSec=0` to keep retrying until PostgreSQL is available. |
| **AC-09** | WebSocket (e.g. Home Assistant) | **Done** (scoped transport and Companion) | The [published 1.6.1 package](release-evidence/1.6.1-release-acceptance.md#mobile-acceptance-after-upgrade) served the Companion dashboard over mobile data with two `/api/websocket` upgrades and zero HTTP 429 responses during the check. Installed-appliance [WSS on 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#installed-apply-rollback-and-websocket) survived 62s silence and API Apply on the same connection, with confirmed worker replacement, trusted fixture TLS and cleanup. [Candidate 580f5df](release-evidence/1.6.1-websocket-580f5df.md) passed HAProxy 101, masked-frame echo beyond shortened HTTP idle limits and MCP-only denial with race detection. |
| **AC-10** | Backup + restore | **Done** (scoped VMware copy) | [Installed 6fe3be2](release-evidence/1.6.1-local-gates-6fe3be2.md#amd64-offline-appliance-installation) recovered fixture database, state, configuration and trusted readiness after backup and restore. Actual backup/factory-reset/restore E2E passed on [b5fa4a4](release-evidence/1.6.1-restored-copy-b5fa4a4.md). Installed restore also passed [without a source checkout](release-evidence/1.6.1-packaged-restore-677a499.md) and [with shared-lock and preflight checks](release-evidence/1.6.1-restore-lock-74b0df7.md). The [restore follow-up](release-evidence/1.6.1-restore-d5f7475.md) checked stop refusal, recovery errors and trusted HTTPS after restore. The [backup follow-up](release-evidence/1.6.1-backup-2bdeca3.md) verified a preserved archive on stop refusal, a restorable new archive on restart refusal and recovery. The [pristine install follow-up](release-evidence/1.6.1-pristine-vmware-9d7dbc8.md) verified the timer schedule before reboot. These are same-version amd64 checks. See [backup and restore](BACKUP_RESTORE.md) for the operator procedure. |

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
9. **UI:** continue [JavaScript source separation](WEBUI_MAINTAINABILITY.md#3-split-javascript-by-responsibility). The Go generator assembles all screen partials into the embedded page. See [deployed bundle verification](WEBUI_MAINTAINABILITY.md#verify-the-deployed-bundle) when a running panel appears out of date.
10. **OpenClaw publication template:** the [Gateway profile and example](OPENCLAW.md) cover Control UI with HTTPS, WebSocket and Gateway authentication. HAProxy integration covers forwarding metadata, the UI settings path and upgraded transport. Pairing with a deployed OpenClaw Gateway is a separate acceptance check.

Update this file when closing MVP items and when `VERSION` changes.

## Golden tests: **Done**

`Render()` fixtures → snapshots `internal/haproxy/testdata/golden/<scenario>.cfg` + `<scenario>.crt-list.txt`; refresh: `make golden-update` (`UPDATE_GOLDEN=1`). Unit test: `go test ./internal/haproxy/... -run Golden`. Integration `haproxy -c` on golden files: `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (see `render_golden_integration_test.go`).

## CI (GitHub Actions)

| Requirement | Status | Where |
|-------------|--------|-------|
| `go vet`, golangci-lint, `go test -run Golden` (HAProxy golden), `go test -race` (with `-skip TestGoldenRender` to avoid duplicating golden), Linux artifact / LF checks for `scripts/**/*.sh`, `haproxy -c` on generated config + golden (`-tags=integration`), store/engine/auth integration tests against a PostgreSQL 16 service container | **Done** | `.github/workflows/ci.yml`, `internal/haproxy/render_golden_test.go`, `internal/haproxy/haproxy_validate_test.go` |
| Container end-to-end: the body policy and CrowdSec decisions against HAProxy 2.8 with a real LAPI and bouncer | **Done** | [`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml), nightly and on demand; `scripts/test-body-policy-e2e.sh`, `scripts/test-crowdsec-e2e.sh` |
