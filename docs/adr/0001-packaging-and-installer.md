# ADR 0001 — Packaging: how Easy Home WAF gets onto an appliance

- **Status:** accepted
- **Date:** 2026-08-16
- **Deciders:** repository maintainer
- **Context version:** 1.3.0
- **Implemented in:** `packaging/nfpm.yaml`, `packaging/deb/`, `make deb`,
  `release.yml`, `scripts/install.sh` (unreleased at the time of writing)

## Context

Today there is exactly one supported way to install: clone the repository on the
target host and run `scripts/install.sh` as root. That script does a lot:

1. creates the `easy-waf` user and the `/var/lib/easy-waf` layout;
2. installs OS packages (HAProxy, nftables, fail2ban, PostgreSQL, CrowdSec + SPOA);
3. **acquires binaries** — tries the GitHub release tarball for the version in
   `VERSION`, verifying it against `SHA256SUMS`; otherwise installs the **Go
   toolchain, make and git via apt** and builds from source on the appliance;
4. writes `/etc/easy-waf/easy-waf.env`, installs systemd units, configures
   nftables, provisions the database, and starts the services.

This works, and it is why the project got this far. It also has problems that get
worse the moment the repository is public and strangers install it:

- **A build toolchain on a security appliance.** The fallback path installs Go,
  make and git on the box that terminates TLS for someone's home network, and
  leaves them there. That is a large, permanent attack surface added for the sake
  of a first install.
- **Cloning the repository is a prerequisite.** `git` plus network access to
  GitHub is required just to get a script that then downloads a tarball. Nothing
  about the appliance needs a git checkout at runtime.
- **No dependency declaration.** The script installs packages imperatively; there
  is no manifest a system can reason about, and no failure until something is
  missing at runtime.
- **Upgrade, downgrade and uninstall are undefined.** `scripts/upgrade.sh` exists,
  but nothing tracks which files belong to the product. There is no way to remove
  it cleanly, and no way to answer "which version is installed" except reading
  `VERSION` from a checkout that may have moved on.
- **Configuration files are not protected.** `/etc/easy-waf/easy-waf.env` is
  hand-managed; an install that overwrote it would take the appliance offline
  and there is no `conffile` machinery to prompt or preserve.
- **A first impression that reads as unfinished.** A public "curl a repo and run a
  bash script that may compile Go on your firewall" is a hard sell for exactly the
  audience that cares about a WAF.

The platform is fixed and narrow — **Ubuntu 24.04 LTS only** — which removes most
of the usual packaging complexity from consideration.

## Options considered

### A. Keep the status quo (tarball + `install.sh`)

Zero work. Keeps every problem above. The recent `SHA256SUMS` verification
(1.2.0) and the origin-remote derivation (1.3.0) fixed the worst of it — releases
are now verified when they are found — but the source-build fallback and the
undefined lifecycle remain.

### B. Native `.deb` package — *recommended*

Ship `easy-waf_<version>_amd64.deb` as a release asset.

- `Depends:` declares haproxy, nftables, fail2ban, ca-certificates; `Recommends:`
  postgresql (so an external-database install is a supported shape rather than a
  flag); `Suggests:` crowdsec.
- Binaries land in `/usr/sbin`, units in `/lib/systemd/system`, defaults in
  `/usr/share/easy-waf`.
- `/etc/easy-waf/easy-waf.env` is a **conffile**: dpkg preserves local edits and
  prompts on conflict — the single most valuable property for an appliance whose
  configuration is a secret-bearing env file.
- `postinst` creates the user and directories, runs `systemctl daemon-reload`,
  enables units on first install; `prerm`/`postrm` stop services and, on purge,
  remove state deliberately rather than by accident.
- `apt install ./easy-waf_1.3.0_amd64.deb` gives dependency resolution, a clean
  `apt remove` / `apt purge`, and `dpkg -l` as the answer to "what is installed".
- Upgrades become `apt install` of a newer file (or an apt repository later),
  with migrations still handled by the API on start.
- No compiler, no git, no toolchain on the appliance.

Cost: a packaging definition and maintainer scripts, plus a build step in
`release.yml`. With [nfpm](https://nfpm.goreleaser.com/) this is a YAML file and
one command — no Debian tooling, no `debian/rules`, and it runs in the existing
ubuntu-latest runner. `install.sh` shrinks to "provision the environment and hand
over to dpkg", or stays as the from-source path for developers only.

### C. Self-extracting `.run` bundle

A single executable file with binaries, units, configs and scripts appended; runs
without git, network, or a package manager.

Genuinely useful for air-gapped installs, and it is the only option here that
needs nothing but a file copy. But it reimplements what dpkg already does — file
ownership, upgrade, removal, conffile handling — and does it worse, because each
of those becomes bespoke script logic that has to be tested. As a *primary*
mechanism it is a step sideways; as a *complement* to B for isolated networks it
is a thin wrapper that carries the `.deb` and calls `apt install ./…`.

### D. Container image

Does not fit. The product manages nftables, netplan, systemd units and the host's
HAProxy; a container that needs `--privileged` and the host network namespace is
a lie about isolation. Rejected on the same grounds the project already rejected
supporting distributions other than Ubuntu.

### E. OVA / appliance image only

Already documented in [DEPLOYMENT.md](../DEPLOYMENT.md) as a distribution shape,
and it composes with B rather than competing: the image is built *by installing
the package*. Not a substitute for a package, because it cannot upgrade.

## Decision

**Adopt B — a native `.deb` as the primary installation and upgrade mechanism** —
and keep the release tarball for developers and for anyone who wants to place
binaries by hand.

Build C (`.run`) only if a concrete air-gapped requirement appears, and then as a
carrier for the `.deb`, not as a second packaging format with its own lifecycle
logic.

Rationale, shortest form: the platform is a single Debian-family LTS, dpkg already
solves dependency declaration, conffile preservation, upgrade and clean removal,
and every one of those is currently unsolved. The alternative is to reimplement
dpkg in bash on a security appliance.

## Consequences

Positive:

- No build toolchain on the appliance; the source-build fallback becomes a
  developer path rather than an end-user one.
- `apt remove` / `apt purge` become real, which also makes testing on the pilot
  host repeatable.
- `/etc/easy-waf/easy-waf.env` gets dpkg's conffile handling — upgrades stop being
  a risk to the operator's configuration.
- The install instruction becomes two lines that a stranger can audit before
  running.

Negative / accepted cost:

- Another artifact to build, sign and verify. `SHA256SUMS` must cover the `.deb`,
  and the existing verification logic in `scripts/lib/release-verify.sh` should be
  reused rather than duplicated.
- Maintainer scripts (`postinst`, `prerm`, `postrm`) are a new class of code that
  runs as root at install time; they need the same review standard as
  `easy-waf-hostd` and must be idempotent.
- Two installation paths to document and keep working until the script path is
  narrowed to developers.
- An apt repository (signed, hosted) is *not* part of this decision — the package
  is a release asset. Repository hosting is a separate ADR when it is needed.

## Implementation sketch

1. `packaging/nfpm.yaml`: contents, dependencies, conffiles, systemd units.
2. `packaging/deb/postinst|prerm|postrm`: user and directory creation
   (reusing what `install.sh` does today), `daemon-reload`, enable on first
   install, stop on removal, state handling on purge. Idempotent, `set -e`, no
   network access.
3. `release.yml`: build the `.deb` alongside the tarball, add it to `SHA256SUMS`,
   attach both to the release.
4. `scripts/install.sh`: prefer the `.deb` when present for the target version —
   verify, `apt install ./file.deb`, then continue with the parts a package cannot
   do (PostgreSQL provisioning, nftables policy, CrowdSec bootstrap, enrollment).
5. Docs: QUICKSTART gets a package-first install; DEPLOYMENT documents both paths
   and the upgrade/rollback story; a new section in OPERATIONS on
   `apt remove` vs `purge` and what survives.
6. Verification: install on a clean Ubuntu 24.04 VM, upgrade from the previous
   version, edit the env file and upgrade again to confirm the conffile prompt,
   then `apt purge` and check what is left. `scripts/smoke-appliance.sh` after each.

## Open questions, as resolved during implementation

- **Does the source-build fallback stay?** Yes, behind `EASY_WAF_BUILD_FROM_SOURCE=1`.
  When `VERSION` names a release and neither the `.deb` nor the tarball can be
  downloaded and matched against `SHA256SUMS`, the installer now stops and says
  why. Silently compiling in that situation is the wrong reflex: it means the
  release is missing, the repository is wrong, or something other than GitHub
  answered — and the response was to install a toolchain and run a build. A
  development checkout (no release version) still builds without a flag.
- **Package signing:** unchanged — release-asset checksums for now. A signed apt
  repository changes the trust model and gets its own record.
- **Does `easy-wafd` ship in the package?** No. It is the same binary as
  `easy-waf-api` under a second name; packaging it would put an enable-able
  second copy of the control plane on every new install, and two of them sharing
  one state directory is a failure mode with no upside. Existing appliances keep
  the file `install.sh` gave them — the package does not own it — and `postinst`
  warns if `easy-wafd.service` is enabled.
- **What `apt purge` removes** was not in the original sketch and had to be
  decided: configuration yes, `/var/lib/easy-waf` no. dpkg cannot distinguish
  "done with this appliance" from "reinstalling" or "moving hosts", and that
  directory holds TLS private keys, certificates from rate-limited ACME accounts,
  the JWT signing secret and the rollback history. `postrm` prints the path and
  the command instead. Same call PostgreSQL makes about its clusters.

## Follow-ups this record does not cover

- Narrowing `scripts/install.sh` to provisioning only, once the package path has
  been exercised on real upgrades.
- An OVA built by installing the package (option E), rather than by running the
  installer inside the image.
