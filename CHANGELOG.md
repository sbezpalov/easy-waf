# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`easy-waf-admin doctor`**: Comprehensive appliance diagnostic command and self-test suite (storage permissions, PostgreSQL connectivity & schema migrations, HAProxy edge syntax `haproxy -c`, systemd services status, GeoIP MMDB freshness, TLS certificate expiry) with human-readable colorized and `--json` outputs.
- Comprehensive unit test suites for previously untested packages: `internal/apply`, `internal/audit`, `internal/blockedua`, `internal/mgmttls`, `internal/pemutil`, and `internal/admin`.

### Security

- Management API/UI security headers hardened in `internal/api/security_middleware.go`: added `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `X-Permitted-Cross-Domain-Policies: none`, and `Strict-Transport-Security: max-age=31536000; includeSubDomains` (on HTTPS/TLS requests).
- Standardized security-restricted file write permissions (`0o600`) across all sensitive configuration and credential files.

### Performance

- Pre-compiled HAProxy configuration text templates (`template.Must`) in `internal/haproxy/render.go` to eliminate template parsing overhead on edge config rendering.
- Pre-allocated memory slice buffer capacities across key rendering and processing routines (`haproxy`, `ipbl`, `ipwl`, `geoip`, `admin`, `host/apt`, `metrics`).

### Fixed

- macOS (`darwin`) Unix domain socket path length limitation in runner and hostd test suites via short temp socket helper.
- Resolved all `revive`, `gocritic`, `gosec`, and `prealloc` linter warnings across core binaries and test files.

## [1.1.0] - 2026-07-11

### Added

- System → Updates: **live streaming log** for `apt upgrade` (`POST /api/v1/host/updates/upgrade/stream`, NDJSON via `easy-waf-hostd` `apt-upgrade-stream`)
- System → Updates: **Clean up (autoremove)** with preview (`GET …/autoremove/preview`) and live log (`POST …/autoremove/stream`); shared apt single-flight in hostd
- System → Updates: **disk usage indicator** (`GET /api/v1/host/disk`, `statfs` without root) and **Clean apt cache** (`POST …/updates/clean`, `apt-get clean` via broker)
- **Users** tab: list/create/delete local accounts; SSH authorized keys editor (`GET/POST/DELETE /host/users`, `PUT …/ssh-keys`); audit events `host_user_*`
- `GET /api/v1/host/updates/upgrade/status` and `GET …/upgrade/log`; re-attach to a running upgrade instead of rejecting with `-1`

### Fixed

- Apt-upgrade live stream: flush via `ResponseController` (lines visible during run), heartbeat while apt is silent, `DPkg::Lock::Timeout=120`, attach followers to running upgrade

### Changed

- Fail2ban status/unban routed through **`easy-waf-hostd`** (`fail2ban` opcode); retired fail2ban group/socket/sudoers access for **`easy-waf-api`**
- Replaced sudo `host-privileged.sh` helper with root unix-socket broker **`easy-waf-hostd`** (`/run/easy-waf/hostd.sock`); **`easy-waf-api`** stays hardened (`NoNewPrivileges`, `ProtectSystem=strict`)
- `scripts/lib/crowdsec-install.sh`: after `apt install crowdsec`, wait for LAPI and auto-recover from transient postinst / watcher auth failures so a clean VM finishes **`install.sh`** in one run
- `scripts/install.sh`: appliance base packages no longer install `nginx`; edge remains HAProxy-only to avoid extra attack surface and port conflicts
- Platform: **Ubuntu 24.04 LTS only** — dropped AlmaLinux/RHEL support; host firewall is **nftables** (not firewalld); docs and CI aligned to `ubuntu:24.04`
- Host management API (`/api/v1/host/*`): network, nftables, services, journal, apt, users/SSH keys

### Security

- Broker peer authentication: `easy-waf-hostd` enforces `SO_PEERCRED`, accepting connections only from uid `0` or `easy-waf`; socket is `root:easy-waf 0660` in `/run/easy-waf` (`0750`)
- Allowlisted opcode dispatch only — unknown opcodes rejected; strict argc checks and validators (`ValidToken`, `ValidStagedPath`, `ValidUsername`, `ValidJailName`, `ValidIP`, journal arg allowlist) on every privileged path
- SSRF protection for external IPBL feeds (blocks private/special-use IPs); split-DNS resolvers for ACME DNS-01 propagation checks
- Timed rollback for nftables/netplan via transient `systemd-run` timer with token-scoped backups (auto-revert unless committed)

## [1.0.0] - 2026-04-16

### Added

- Per-application security layer toggles with mode presets (full/balanced/trusted-lan/reverse-proxy-only/custom)
- CI pipeline: Ubuntu 24.04 LTS, golangci-lint, golden tests, haproxy -c integration
- HAProxy stats socket metrics (Dashboard, GET /api/v1/stats/*)
- GeoIP batch enforcement (ipinfo.io provider + LRU cache)
- IP Allowlist (whitelist) + IP Blacklist with external feeds
- Basic WAF rules (SQLi/XSS/traversal) per-app toggle
- UA bot blocking (empty UA + pattern map)
- CrowdSec non-interactive install (`EASY_WAF_INSTALL_CROWDSEC` + `AUTO_START`, apt packages)
- Audit log with UI (filter, pagination, auto-refresh)
- Certificate dashboard (summary, expiring/expired counts)
- Backup/restore with E2E test
- Rollback via UI (revision list + one-click rollback)
- Ubuntu 24.04 LTS as the sole supported platform (apt, nftables)
- Management TLS (self-signed bootstrap + hot-reload replacement)
- Dual listener HTTP 8000 + HTTPS 8443

### Fixed

- CRLF auto-cleanup in install.sh (Windows → Linux)
- systemd: no `${VAR:-default}` in ExecStart
- pg_hba.conf scram-sha-256 for easywaf on TCP localhost
- db-password.sh regex group escape
