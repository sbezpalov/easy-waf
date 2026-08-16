# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-08-16

### Added

- **GeoLite2 database upload from the UI** (**Security → GeoIP → Upload & install**, `POST /api/v1/geoip/database`): accepts a `.mmdb` file or the `.tar.gz` MaxMind publishes, installs it into `<state>/geoip/` and hot-swaps the reader — no shell access, no `scp`, no restart. Previously the file had to be placed on the appliance by hand or by the cron script, and the UI could only point at an existing path.
  - The archive format is detected from the content, not from a file name; `.tar.gz` member paths are ignored, so a crafted archive cannot choose where bytes land.
  - The destination name comes from the database's own metadata (`GeoLite2-Country.mmdb` / `GeoLite2-City.mmdb`), never from the request.
  - The upload must open as a MaxMind database with country data and answer a lookup for `8.8.8.8` before an atomic rename installs it — **a rejected upload leaves the running database in place**.
  - Decompressed size is capped at 128 MiB, installs are serialized, and each one is recorded in the audit log as `geoip_database_uploaded`.
  - A refresh of an already-configured database (`geoip_mmdb_path` already points at the installed file) hot-swaps the reader and clears the lookup cache — `"reloaded": true`. A first install reports `"reloaded": false` with an `activate_hint`, because the runtime resolves its reader from `geoip_mmdb_path`; the UI fills the path in and prompts to save.
- `internal/geoip`: `ValidateMMDBFile`, `ExtractMMDB` and `InstallMMDB` for reuse outside the API handler.

### Changed

- `limitRequestBody` takes an exemption list so a single large-artifact route can opt out of the global 4 MiB cap while still enforcing its own limit in the handler.
- `scripts/install.sh` creates `<state>/geoip` owned by `easy-waf`, and `scripts/update-geoip-db.sh` restores that ownership when it runs as root — otherwise a root-created directory would block UI uploads.
- **Migrations are split by a real SQL scanner** instead of `strings.Split(sql, ";")`. The old splitter would have executed the first migration containing a dollar-quoted block (`DO $$ … END IF; … $$;`), a semicolon inside a string literal, or a quoted identifier as several broken fragments. The scanner tracks string literals, quoted identifiers, dollar quotes (including tagged ones), line comments and nested block comments. A test asserts the new splitter yields byte-identical statements for all 18 shipped migrations, so upgrading an existing appliance changes nothing.
- `easy-waf-hostd` copies files atomically (temp file plus rename). The previous read-then-write left a window where the live nftables ruleset or netplan configuration was truncated — during rollback, which is when it is least recoverable.
- `internal/mapfile.HasEntries` replaces the identical copies in `ipbl` and `ipwl`, so "map file is empty" cannot drift between the generators.
- `blockedua` deduplicates patterns like the other map generators; duplicate rows previously produced duplicate map lines on every apply.
- ACME account keys are generated through one policy constant; the two branches of `loadOrCreatePrivateKey` used different code paths for the same decision.

### Fixed

- **CI is green again.** Two of the three jobs had been failing since before this release series. `haproxy-config-test` could not pass anywhere except the appliance the fixtures were written for: `backend-tls-custom-ca.cfg` records the operator CA path `/etc/easy-waf/ca/lab.pem` and `haproxy -c` opens `ca-file` for real — the integration test now redirects `ca-file` at a committed certificate fixture, like it already did for the stats socket, and all 25 golden configs validate. `go test -race` reported a genuine data race on `aptActionHeartbeatInterval`, a package variable a test restored while the heartbeat goroutine still read it; it is an atomic now.
- Remaining `gosec`/`revive` findings cleared, so `golangci-lint run ./...` with the pinned v1.62.2 is clean: the nftables revert writes through `writeFileAtomic` with the same mode constant the apply path uses (atomic, no permission drift), `openatBeneath` takes `uint64` flags, and the MMDB build epoch is bounds-checked before conversion.

## [1.2.1] - 2026-08-16

### Added

- **`POST /api/v1/auth/logout`** revokes every JWT issued to the operator (increments `users.session_version`); the UI calls it before clearing the local token, so signing out is enforced server-side instead of only in the browser.
- Optional **`EASY_WAF_METRICS_TOKEN`** (≥16 characters) locks `/metrics` behind a bearer token for Prometheus, which cannot present a session JWT. Without it the endpoint remains protected only by `management_allowed_cidrs` (RFC1918 by default).

### Security

- **`easy-waf-hostd` no longer lets SSH key management escalate to root.** The broker now re-validates `authorized_keys` content itself (`hostspec.ValidateAuthorizedKeysContent`) instead of trusting the API-side check, rejecting option-bearing lines (`command=`, `environment=`, `permitopen=`) that execute code on every login, plus size and line-count limits. Accounts in a root-equivalent group (`root`, `sudo`, `admin`, `wheel`) are refused unless the operator sets `EASY_WAF_HOSTD_ALLOW_PRIVILEGED_SSH_TARGETS=1` in the root-owned `easy-waf-hostd` unit; an unreadable `/etc/group` fails closed.
- `authorized_keys` writes no longer follow symlinks: `~/.ssh` and the key file are opened relative to the home directory with `openat2` (`RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS`), ownership and mode are applied through the descriptor, and the file is swapped in with `renameat`. The previous `install -d -o user ~/.ssh` resolved the destination as root, so a local account could redirect a root-side `chown`/write into another directory.
- Broker peer authentication fails closed: when the `easy-waf` account cannot be resolved at startup, `SO_PEERCRED` checking used to be skipped for every connection — now only root is accepted, and a non-unix connection is rejected outright.
- **Per-application HAProxy ACL tags are no longer ambiguous.** `-` and `_` both collapsed to `_`, so applications `pay-api` and `pay_api` shared one ACL name; HAProxy ORs same-named ACLs, which silently applied one application's IP blacklist, GeoIP, WAF and routing rules to the other application's host. Identifiers now preserve `-`, making the mapping injective over the validated ID charset (generated backend names change accordingly, e.g. `bk_waf_on_example_com` → `bk_waf-on_example_com`).
- Legacy `EASY_WAF_ADMIN_TOKEN` is compared as a fixed-width SHA-256 digest instead of `len(raw) == len(token)` followed by a constant-time compare, which leaked the token length; tokens shorter than 24 characters are now ignored with a startup warning rather than accepted.
- **Application fields are re-validated at render time** (`config.ValidateApplicationRenderSafety`), not only in the API handler. `public_host`, `backend_host`, `name`, paths, restricted-path CIDRs and `backend_tls_server_name` are interpolated straight into HAProxy directives, where a newline injects a rule that `haproxy -c` still accepts; the generator no longer assumes the API handler was the only way a row could be stored.
- `backend_tls_server_name` is restricted to DNS/IP characters — parentheses previously broke the generated `sni str(<name>)` expression and made the whole edge config fail to load.
- Session JWTs are parsed with `WithExpirationRequired()` and `WithIssuedAt()`: a signed token without `exp` used to be accepted and never expire.
- `POST /api/v1/auth/change-password` is rate-limited per IP like login — it verifies `current_password`, so it was an unthrottled password oracle for a session holder.
- Login no longer answers faster for unknown usernames: a dummy bcrypt comparison equalizes the timing that revealed which operator names exist.
- The login rate limiter caps its per-IP table at 10 000 entries and evicts the least recently seen address; a spray of distinct source IPs previously grew the map unboundedly between the one-minute sweeps.
- `easy-waf-hostd` rollback flushes the ruleset when the nftables backup is empty. A revert after "no managed ruleset existed" used to leave the newly applied rules live — including the automatic revert that fires when an operator locks themselves out.
- `scripts/update-geoip-db.sh` passes the MaxMind license key and the API bearer token through `curl --config -` instead of argv, where any local user could read them from `ps`.
- `scripts/restore.sh` refuses archives containing absolute or `..` paths and extracts with `--no-same-owner --no-same-permissions`, so an operator-supplied backup cannot restore attacker-chosen ownership as root.

### Changed

- `internal/host/users.ValidateSSHPublicKeys` delegates to `hostspec` so the API and the broker cannot drift apart.
- The `easy-waf-hostd` unit now sets `ProtectHome=false` with an explanation. `ProtectHome=true` makes `/home` appear empty to the service, so `PUT /host/users/{name}/ssh-keys` could never write a key — the endpoint was silently inoperative. That path is guarded by the three controls above instead of by hiding the directory; set it back to `true` if you never manage keys from the UI.

## [1.2.0] - 2026-08-15

### Added

- **`easy-waf-admin doctor`**: Comprehensive appliance diagnostic command and self-test suite (storage permissions and space, read-only PostgreSQL connectivity and security-schema checks, HAProxy edge syntax `haproxy -c`, systemd services status, GeoIP MMDB freshness, TLS certificate expiry) with human-readable and `--json` outputs.
- Comprehensive unit test suites for previously untested packages: `internal/apply`, `internal/audit`, `internal/blockedua`, `internal/mgmttls`, `internal/pemutil`, and `internal/admin`.
- `scripts/lib/release-verify.sh`: shared SHA-256 verification helper for downloaded release artifacts, with offline regression tests (`make test-release-verify`, wired into `make verify`).

### Security

- **Release artifacts are now integrity-checked before installation.** `scripts/install.sh` and `scripts/download-release.sh` fetch `SHA256SUMS` from the same GitHub release and refuse any tarball with a missing or mismatched digest (installer falls back to building from source); `EASY_WAF_RELEASE_URL` requires an explicit `EASY_WAF_RELEASE_SHA256`. Previously TLS was the only control on binaries installed to `/usr/sbin` as root. Override for mirrors without checksums: `EASY_WAF_ALLOW_UNVERIFIED_RELEASE=1`.
- Release downloads use `curl --proto '=https' --proto-redir '=https' --tlsv1.2` — no plaintext hop, including through redirects.
- Release tarballs are downloaded into `mktemp -d` instead of predictable `/tmp/easy-waf-rel.tgz`, `/tmp/easy-waf-release.tgz` and `/tmp/easy-waf.tgz`: root `curl -o` follows symlinks, so a local user could pre-create those paths and have root truncate an arbitrary file.
- `scripts/lib/db-password.sh` no longer prints the rotated PostgreSQL password to stdout (install logs are commonly redirected to files); it now verifies it can persist the value *before* `ALTER USER`, falls back to `sed` when `python3` is absent, and as a last resort stores the password in a `0600` file, logging only the path.
- Management API/UI security headers hardened in `internal/api/security_middleware.go`: added `Permissions-Policy: camera=(), microphone=(), geolocation=()`, `X-Permitted-Cross-Domain-Policies: none`, and `Strict-Transport-Security: max-age=31536000; includeSubDomains` (on HTTPS/TLS requests).
- Standardized security-restricted file write permissions (`0o600`) across all sensitive configuration and credential files.
- Made backend TLS migration 018 repeat-safe so service restarts cannot silently change operator-selected `verify required` to `verify none`.
- Made `easy-waf-admin doctor` use a non-migrating connection and PostgreSQL read-only transaction; the installer now defaults to HTTPS-only loopback management.

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
