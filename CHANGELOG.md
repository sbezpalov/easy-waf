# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.4.2] - 2026-09-15

Five defects the documentation pass turned up, and the documentation pass itself.

The one that matters: **a stock appliance was not validating or reloading
HAProxy.** `configs/defaults/easy-waf.env.example` shipped
`EASY_WAF_SKIP_RELOAD=0` and `EASY_WAF_SKIP_VALIDATE=0` *uncommented*, and the
code read any non-empty value as "set" — so `0` switched both off. Apply wrote a
configuration that was never checked with `haproxy -c` and never loaded by the
running HAProxy, and reported success. The lines have been there since the first
commit. Upgrading fixes it without editing anything: `0` now means off.

**Upgrade note.** Nothing to do by hand. After upgrading, an apply will do what it
always said it did — which on an affected appliance means HAProxy picks up
everything that accumulated in the database since the last manual reload. Look at
the generated config first if that gap is large:
`easy-waf-admin apply-edge` after `haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg`.
Whether this bit you at all is recorded: an apply that skipped the reload wrote
`"skipped_reload": true` into its audit detail.

### Fixed

- **`EASY_WAF_SKIP_VALIDATE`, `EASY_WAF_SKIP_RELOAD`, `EASY_WAF_ACME_SKIP_APPLY` and `EASY_WAF_NO_AUTO_APPLY` are parsed as booleans.** They were read with `os.Getenv(...) != ""`, which makes `0` mean *on* — the opposite of what the shipped env file, and every reader of it, intended. They now go through `internal/envflag`: `1`/`true`/`yes`/`on` enable, `0`/`false`/`off`/empty/unset disable, and a value that is neither is treated as **off** and logged once, because a typo must not be the thing that disables a safety check. `easy-waf.env.example` no longer sets any of them, and says why.
- **A re-issue with no `mode` keeps the certificate's mode instead of forcing `http-01`.** The UI's Issue and Renew buttons both `POST` an empty body, so renewing a DNS-01 certificate through the UI rewrote the row to `http-01` and the next `easy-waf-acmed` pass attempted a challenge the domain may not answer. A certificate not yet on an ACME mode still starts on `http-01`; an explicit mode that is neither `http-01` nor `dns-01` is now rejected with 400 rather than stored.
- **The rendered `bk_acme` backend follows a setting instead of a hardcoded address.** `EASY_WAF_ACME_INTERNAL_HTTP` moved the HTTP-01 listener while the generated config kept `server acme 127.0.0.1:8089`, so using the variable as documented silently broke HTTP-01. The address is now the global setting **`acme_internal_http`** (default `127.0.0.1:8089`, `ip:port`, validated on write *and* at render like every other interpolated value), which both the listener and the renderer read — the rendered config is a function of the database, as it has to be when three binaries render it. The environment variable still switches the helper off, and `easy-waf-api` now logs a warning if it is used to move the listener away from what the backend dials.
- **`easy-waf-admin doctor` checks the stats socket that exists.** It probed a hardcoded `/run/haproxy/admin.sock`, which has not been the default since the socket was renamed, and the whole check sat behind "if the file exists" — so on a stock appliance it silently reported nothing. It now reads the path out of the generated `haproxy.cfg`, falls back to the current default, and reports a missing socket as a warning instead of saying nothing.
- **Diagnostics bundles collect `easy-waf-hostd`.** Both the API bundle and `scripts/diagnostics.sh` gathered status and journals for the API, acmed and HAProxy but not the root broker — so a bundle taken after a failed host update, firewall apply or user change was missing the one unit that could explain it.

### Changed

- **The build-time specification is gone, and the status matrix stands on its own.** The root `prompts.md` was the prompt the project was built from: fully executed (Done 20, Partial 1, Missing 0) and, by 1.4.1, contradicted by the result — it prescribed a `/web`, `/templates`, `/tests` layout that does not exist, and an acceptance criterion of "SELinux remains enabled" on an appliance that targets Ubuntu with AppArmor and nftables. A reader arriving at the repository met a stale map competing with the real documentation. What was worth keeping — the requirements, the acceptance criteria AC-01 … AC-10, and where each one is implemented — is [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md), formerly `docs/PROMPTS_ALIGNMENT.md`, now written to be read on its own rather than as a diff against a document that no longer exists. `AGENTS.md`, `README.md`, `README.ru.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/SECURITY.ru.md` and `docs/adr/README.md` point at it.
- **The fallback reporting channel in [`SECURITY.md`](SECURITY.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) is one that exists.** Both pointed at "the email address in the repository owner's GitHub profile", which that profile does not publish — a dead end for anyone who cannot use private advisories. They now point at the profile's contact links. GitHub private vulnerability reporting remains the primary channel.
- **Attribution now travels with the code.** `NOTICE` names the original author rather than only "Easy Home WAF contributors", and every Go source file carries a two-line `Copyright` / `SPDX-License-Identifier: Apache-2.0` header. Apache-2.0 §4(c) obliges a derivative to keep `NOTICE`, so that file is where authorship survives a fork — and the per-file header is what survives when somebody copies a single file rather than the repository. Both READMEs now state the obligations in a sentence, including §6: the licence grants no rights to the project's name.
- **CI and release workflows run on current actions** — `actions/checkout` v7, `actions/setup-go` v7, `softprops/action-gh-release` v3.
- **Documentation caught up with the code, and four instructions that would have failed an operator are corrected.** A pass over every document against `HEAD` found the reference guides had drifted furthest — `docs/ACME.md`, `docs/DNS01.md`, `docs/HOST-API.md`, `docs/DIAGNOSTICS.md`, `docs/DNS.md`, `docs/FAIL2BAN.md` and `docs/VM-REQUIREMENTS.md` had not been revised since May while the appliance grew a root broker, GeoIP, and packaging. The four that were actively wrong: the DNS-01 credentials file is **readable by `easy-waf`**, not root-only as `docs/ACME.md` said (`easy-waf-acmed` runs as that user and opens the file itself, so a file only root can read fails every issuance — `docs/DNS01.md` had this right all along); `POST /certificates/{id}/request-issue` with an empty body rewrote the stored row to `http-01` (fixed above); `EASY_WAF_ACME_INTERNAL_HTTP` could not move the HTTP-01 listener, because the rendered HAProxy backend hardcoded `127.0.0.1:8089` (fixed above); and the "separate `crt` + `key`" PEM layout does not exist — a certificate resolves to exactly one file on the `crt-list` line. Alongside those: secrets live under the **state** directory, not `/etc/easy-waf/secrets`; `easy-waf-hostd` is now named everywhere the other two daemons are (release tarball, OVF checklist, `systemctl enable`, VM sizing); `/var/log/easy-waf/` never existed; and `upgrade.sh` re-runs the whole installer rather than swapping a binary.
- **`docs/IMPLEMENTATION_STATUS.md` now adds up.** Its summary counts were carried over from the retired spec unchanged and did not match the tables under them — Done 20 against 36 actual, and the acceptance criteria were not summarised at all. Three rows had unclosed `**` markers left by the retirement edit, which GitHub rendered literally. The UI row still said 8 tabs against the 11 in `internal/webui/dist/index.html`. The capability tables keep their `see 7.*` pointers into the feature sections and now also name the package or script that implements each row, so a reader can go straight to the code.
- **Contributor guidance states the two rules the repository now enforces socially rather than in CI** — every new `.go` file carries the `Copyright` / `SPDX-License-Identifier` header, and dependency updates land as reviewed commits because there is no Dependabot. Both in [`CONTRIBUTING.md`](CONTRIBUTING.md); the header rule is also in `AGENTS.md`, which is what the AI tooling reads.

## [1.4.1] - 2026-08-23

A correctness release: the licence the project ships was not the licence it
claimed, and the packaging change that started distributing it landed after the
1.4.0 tag. No code changes, no migration, nothing to do on an appliance beyond
installing the newer package if you want the terms alongside the software.

### Fixed

- **`LICENSE` now contains the Apache-2.0 text.** It held the boilerplate *header* — the "Licensed under the Apache License… You may obtain a copy at ‹URL›" notice meant for the top of a source file — and not the licence itself. Apache-2.0 §4(a) requires giving every recipient a copy of the License, GitHub's detector does not recognise a stub, and `NOTICE` pointed at it for "the full license text" that was not there. The file is now the canonical text, verbatim and unmodified, which is also what licence scanners expect; the copyright line stays in `NOTICE`, where it belongs.
- **`LICENSE` and `NOTICE` ship in the package** and in the release tarball (`packaging/nfpm.yaml`, `release.yml`) — installed to `/usr/share/doc/easy-waf/`. An appliance that has the software should have the terms it is under without going back to the repository.

### Added

- **[ADR 0002](docs/adr/0002-mcp-server.md): an MCP server for management and diagnostic verbs.** Proposed, no code — the record exists so the design is settled before anything opens a second way into the control plane. The decision is a separate `easy-waf-mcpd` process on its own loopback port that **calls the REST API as an ordinary client**, so there is still exactly one authorization path and one set of validators; an MCP server holding its own database handle would bypass every check that lives in the API handler, which is the bug class 1.2.1 and 1.4.0 were both spent on. Off unless switched on, read-only by default, its own 32-character credential, audited as a distinct actor, and — the part that answers prompt injection — **no mutating verb executes on its own authority**: `apply` returns a pending change with a rendered diff and the revision it was computed against, and a human confirms that specific change. Binding permission to a diff rather than to a time window is the difference between a control and a formality; a static flag is ambient authority and a short-lived token only narrows the window the injection arrives in. The env flag stays as a kill switch, not as authorization. The two remaining open questions — per-verb scopes, and identity of the caller — carry explicit triggers rather than being left to be remembered, and the one piece that would be expensive to retrofit is decided now: the audit actor is a (kind, name) pair from the start, so a second caller is a column that already exists rather than a migration against a live appliance. And everything that reaches `easy-waf-hostd` — netplan, nftables, systemd, packages, accounts, SSH keys — permanently out of scope, because the broker exists precisely because the API is assumed compromised.

## [1.4.0] - 2026-08-16

### Security

Found by a pre-publication review of the code a stranger sees first. Nothing here is known to have been exploited, and all of it needs a foothold in `easy-waf-api` or a write path into the database that is not the API — which is exactly what the broker's threat model assumes.

- **Three symlink primitives in `easy-waf-hostd` gave a compromised `easy-waf-api` root file access.** `/var/lib/easy-waf` is owned by the unprivileged `easy-waf` account, so anything under it can be replaced with a symlink; the broker runs as root and resolved those paths normally. Reading a rollback backup could be pointed at `/etc/shadow`, whose contents were then copied into `/etc/nftables/easy-waf.nft` at mode 0644 — readable by the same account. Opening a staged file anchored on `/var/lib/easy-waf/staging`, a directory that account can replace, so `RESOLVE_BENEATH` protected a descriptor that had already escaped; the file's contents came back through the `nft -c` parse error. And `os.Create` on the apt action log truncated whatever the symlink pointed at. All three now resolve through the state directory itself — the one component `/var/lib` being root-owned makes unswappable — with `openat2` and `RESOLVE_NO_SYMLINKS`, the technique already used for `authorized_keys` in 1.2.1. New `internal/hostd/statefile*.go`, with tests that assert the primitive works before asserting the broker refuses it.
- **Three fields reached the generated HAProxy configuration without render-time validation**, defeating the point of `ValidateApplicationRenderSafety`: `backend_tls_ca_file` (a newline adds directives to the `server` line — another server, a header, `verify none` on the very connection the field protects), the certificate path fields (a crt-list is one entry per line and an entry may carry an SNI filter, so `*` on an injected line captures certificate selection for every vhost), and every path and identifier in `GlobalSettings` (a newline in `crowdsec_engine_name` plants a bare `http-request allow` that short-circuits every deny after it). All three are now checked in `haproxy.Render`, with the character class shared by the API handler so the two cannot drift.
- **`public_host` accepted uppercase and `_`, and both were silent security failures.** HAProxy matches the Host header with `hdr(host) -i`, so `shop.example.com` and `SHOP.example.com` were two rows whose ACLs both fired on the same request — one application's allow rule short-circuiting another's IP blacklist, GeoIP and WAF denies. And `_` collided with the `.`→`_` identifier mapping, so `a.b.com` and `a_b.com` produced one `bk_a_b_com`; HAProxy rejects duplicate proxy names, which wedged every apply until a row was deleted. Neither character is legal in a DNS hostname. Both are now rejected, and `checkIdentifierCollisions` names both applications if a collision is ever reachable again instead of leaving a duplicate-proxy error and a stuck apply.
- **`easy-waf-admin reset-appliance -bootstrap-credentials` generated a token the API always rejected.** It produced 19 characters against `MinLegacyTokenLen = 24`, so the documented emergency-recovery path wrote a credential to `/etc/easy-waf/easy-waf.env` and `/root/easy-waf-bootstrap-credentials.txt` that could never authenticate — while the startup log said legacy token auth was enabled. It now generates against the constant, so the two cannot drift again.
- **`EASY_WAF_JWT_SECRET` had no minimum length, and `ParseJWT` enforced none at all.** Every other shared secret here fails closed below a floor; the one that yields full management access had none, and the asymmetry was the wrong way round — `SignJWT` refused to sign below 16 bytes while verification accepted anything, so a short operator-set value produced an appliance nobody could log into but anybody who guessed the secret could forge sessions for, with no password check, no rate limit and no failed-login audit record. Minimum is now 32 characters, checked where it is loaded and again on both sign and verify.
- **`scripts/smoke-appliance.sh` wrote scratch files to predictable `/tmp` paths as root.** `postinst` tells the operator to run it after every upgrade; a local user who pre-creates `/tmp/.smoke-body.<pid>` as a symlink — the PID range is small enough to cover exhaustively — got root to write an HTTP response body, or `haproxy -c` output they can influence, into a file of their choosing. Now `mktemp -d` with a cleanup trap.
- **`scripts/restore.sh` had a path-traversal guard that failed open.** `tar -tzf … | grep -q` under `set -o pipefail`: grep exits at the first match, tar dies of SIGPIPE, the pipeline reports failure, the `if` is false — and the archive with the `../` member is extracted anyway. Reproduced with an archive whose first member is `../escaped` followed by padding. The listing is now matched with a here-string, which keeps the producer out of `PIPESTATUS`.

Documentation follows the code: the `public_host` constraint is in [ARCHITECTURE.md](docs/ARCHITECTURE.md), the state-directory symlink rule and the `EASY_WAF_JWT_SECRET` minimum are in [docs/SECURITY.md](docs/SECURITY.md), the `restore.sh` and smoke-test fixes are under its supply-chain section, [ADMIN-CLI.md](docs/ADMIN-CLI.md) has the corrected bootstrap token length, and [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) gains an entry for the "unsafe to render" apply failure an upgraded appliance may hit.

**On upgrade:** an application whose `public_host` contains an uppercase letter or `_` will now fail `POST /apply` with a message naming the application and the field — deliberate fail-closed behaviour, same as 1.2.1 introduced for other stored values. Fix the row and apply again.

### Documentation

- **Three documents are now also in Russian**: [QUICKSTART.ru.md](docs/QUICKSTART.ru.md), [SECURITY.ru.md](docs/SECURITY.ru.md) and [TROUBLESHOOTING.ru.md](docs/TROUBLESHOOTING.ru.md) — the ones an operator reads while installing or while something is broken. English stays canonical and each translated file says so in its header, along with the version it was translated from; `CONTRIBUTING.md` states what a contributor owes when they change one of the three. Code, paths, environment variables and literal error strings are left in English on purpose, because those are what people search for.
- **Two stale claims in the English docs**, both surfaced by translating them: `docs/SECURITY.md` and `docs/DEPLOYMENT.md` still said the installer builds from source when an artifact fails verification — it stops now — and `docs/GEOIP.md` claimed the 128 MiB upload cap applies to decompressed size, which it does not for archive members that are skipped rather than installed.

### Upgrade note

This is the first release with a `.deb`, so the appliance you are upgrading was installed by the script. Back up first (`sudo bash scripts/backup.sh`), then `sudo bash scripts/install.sh` from a 1.4.0 checkout — it downloads and verifies the package, installs it, and retires the units the old script left in `/etc/systemd/system`. Afterwards, upgrades are `apt install ./easy-waf_<version>_amd64.deb`. Verify with `sudo bash scripts/smoke-appliance.sh`.

Two behaviour changes to know before you run it: the installer no longer compiles on the appliance when a release artifact fails to verify (it stops and explains; `EASY_WAF_BUILD_FROM_SOURCE=1` restores the old behaviour), and `easy-wafd` is no longer shipped — disable `easy-wafd.service` if you ever enabled it.

### Added

- **A native Debian package is now the primary way the appliance is installed and upgraded** ([ADR 0001](docs/adr/0001-packaging-and-installer.md), now accepted). Releases publish `easy-waf_<version>_amd64.deb` alongside the tarball, both covered by `SHA256SUMS`. What this changes for an operator:
  - `/etc/easy-waf/easy-waf.env` is a **dpkg conffile**. It holds `DATABASE_URL` with a password and the management listener policy, and an upgrade that overwrote it would take the appliance offline — dpkg now preserves local edits and prompts only on a genuine conflict.
  - `apt remove` and `apt purge` are defined operations, and `dpkg -l easy-waf` answers "which version is installed". `purge` deletes `/etc/easy-waf` but **not** `/var/lib/easy-waf`: it holds TLS private keys, ACME certificates, the JWT secret and the rollback history, and dpkg cannot tell a decommission from a reinstall — `postrm` prints the path and the command instead.
  - Dependencies are declared (`haproxy`, `nftables`, `ca-certificates`, `curl`; PostgreSQL and fail2ban as `Recommends`, CrowdSec as `Suggests`) rather than installed imperatively, so an external-database install is a supported shape instead of a flag.
  - Upgrades restart **only the units that were already running**, so a deliberately stopped service stays stopped.
  - Units now ship in `/lib/systemd/system`. On an appliance installed by the old script, `install.sh` renames any `/etc/systemd/system/easy-waf-*.service` to `*.replaced-by-package` — those override `/lib` and would otherwise make an upgrade look applied while systemd kept starting the previous definition.
  - `easy-wafd`, the legacy alias of `easy-waf-api`, is **not** in the package; a second enable-able copy of the control plane sharing one state directory has no upside. Existing files are left alone, and `postinst` warns if `easy-wafd.service` is enabled.
  - Build it locally with `make deb` (uses [nfpm](https://nfpm.goreleaser.com/)); the maintainer scripts in `packaging/deb/` are linted by `make verify` like the rest of the shell.
- **Documentation for opening the repository**: a root [`SECURITY.md`](SECURITY.md) (private vulnerability reporting, response expectations, what is in and out of scope), [`CONTRIBUTING.md`](CONTRIBUTING.md) (project scope, dev setup, the checks CI runs, code expectations), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), GitHub issue and pull-request templates, and rewritten `README.md` / `README.ru.md` aimed at someone meeting the project for the first time. `internal/haproxy/testdata/golden/certs/README.md` explains that the three test bundles contain throwaway private keys for RFC 2606 domains, so a secret-scanner hit there can be triaged instead of investigated.
- **Architecture decision records** in [`docs/adr/`](docs/adr/), starting with [ADR 0001](docs/adr/0001-packaging-and-installer.md): packaging — the problems with clone-and-run (a Go toolchain left on a security appliance, no dependency declaration, undefined upgrade/uninstall, an unprotected `easy-waf.env`), the options weighed, and the decision to make a native `.deb` the primary install and upgrade path. Proposed; no code yet.
- **`scripts/smoke-appliance.sh`** (`make smoke-appliance`): post-upgrade checks against a live appliance — the things CI structurally cannot prove. Services back up, `easy-waf-admin doctor`, database reachable and migrations applied, `POST /apply` followed by `haproxy -c` on the live config and HAProxy still running, plus the upgrade deltas that only bite a host which ran an older version: units not reloaded (`ProtectHome` on the broker), an `EASY_WAF_ADMIN_TOKEN` under 24 characters that 1.2.1 now ignores, and a root-owned `<state>/geoip` that blocks UI uploads. Optionally exercises the GeoLite2 upload (`EASY_WAF_SMOKE_MMDB`) and verifies that sign-out really revokes a session (`EASY_WAF_SMOKE_USER`/`_PASSWORD`). Read-mostly; non-zero exit on any failure.

### Changed

- **The installer no longer compiles on the appliance by default.** When `VERSION` names a release and neither the `.deb` nor the tarball can be downloaded and verified against `SHA256SUMS`, `scripts/install.sh` now **stops and explains**, instead of installing Go, make and git and building. That situation means the release is missing, the repository is wrong, or something other than GitHub answered — and the old response was to fetch a toolchain and leave it on a machine that terminates TLS. A development checkout (no release version) still builds without a flag; on a released version, opt in with `EASY_WAF_BUILD_FROM_SOURCE=1`, or point at artifacts you already have with `EASY_WAF_DIST_DIR`.
- **`release.yml` fails a tag whose version does not match `VERSION`.** Artifacts are named after the version, so a mismatch produced a release the installer could not find anything in.
- **`docs/DEV_HOST.md` no longer documents one specific machine.** It described a pilot host by internal IP and internal DNS name, which is free reconnaissance in a public repository and useless to everyone else. Rewritten as a generic guide to setting up a Linux development host — SSH config with placeholder addresses, Remote-SSH, and the two checks only a real Linux host can run (`haproxy -c` on the golden configurations, `smoke-appliance.sh` on a live appliance). Concrete addresses belong in `~/.ssh/config`.

### Removed

- **AI working documents (`.ai/artifacts/*`) are no longer tracked**, and the artifact directories of the other tools are ignored too. They are review plans and closure notes: useful while the work is in flight, actively misleading afterwards, since a finding closed in 1.2.1 still reads as open to whoever finds the file later.
- **`.vscode/settings.json` is no longer tracked.** Its only content was a Remote-SSH platform mapping for one developer's host alias; `docs/DEV_HOST.md` now shows where that belongs (user settings).

### Fixed

- **Release downloads pointed at the wrong repository.** `install.sh` and `download-release.sh` hardcoded `easy-waf/easy-waf`, so on a fork or after a rename every artifact request 404s and the installer quietly builds from source — which also means the `SHA256SUMS` verification added in 1.2.0 never actually ran. Both now derive `owner/name` from the origin remote of the checkout they run from (`scripts/lib/github-repo.sh`), still overridable via `EASY_WAF_GITHUB_REPO` / `GITHUB_REPOSITORY`, and fall back to the previous default.

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
