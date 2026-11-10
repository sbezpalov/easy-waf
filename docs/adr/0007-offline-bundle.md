# ADR 0007 — Production offline distribution

- **Status:** accepted
- **Date:** 2026-11-10
- **Deciders:** repository maintainer
- **Context version:** 1.6.0
- **Implemented in:** `scripts/build-offline-bundle.sh`,
  `scripts/install-offline-bundle.sh`, `.github/workflows/release.yml`

## Context

The product package is not self-contained: APT resolves HAProxy, nftables,
PostgreSQL, Fail2Ban and other system dependencies, while CrowdSec comes from a
pinned third-party repository. A disconnected Ubuntu host therefore cannot use
the normal installer from only `easy-waf_*.deb`.

Production use also needs repeatable upgrades, package ownership, conffile
preservation, dependency ordering and offline integrity checks. A tarball of
unmanaged binaries or a bespoke self-extracting installer would duplicate dpkg
and lose those properties.

## Decision

Publish a per-version, per-architecture read-only ISO containing:

1. a flat APT repository with the Easy WAF package and the recursive dependency
   closure for the full appliance profile;
2. APT `Packages` and `Release` metadata;
3. the existing provisioning scripts and non-secret defaults;
4. an internal SHA-256 manifest checked before installation;
5. a package/source manifest for provenance and license review;
6. an external checksum and keyless Sigstore bundle published with the ISO.

The installer accepts Ubuntu 24.04 only, requires the matching architecture and
uses a temporary `APT_CONFIG` that disables all configured source lists. It does
not edit the host's source configuration. CrowdSec's online repository setup is
skipped only under explicit `EASY_WAF_OFFLINE=1` set by the verified carrier.

Before signing, CI verifies the release `.deb` through the already signed release
manifest and asks APT's solver to install the complete profile against an empty
package state using only the generated repository. Bundle payloads are staged
from committed Git objects, not copied from the developer's working tree.

## Consequences

- Native APT/dpkg semantics remain the single install, upgrade and removal path.
- Offline artifacts are larger and must be built natively for both architectures.
- Each ISO freezes Ubuntu and CrowdSec packages at build time. A production
  release process must rebuild the ISO when security packages change; an old but
  authentic ISO can still contain known vulnerabilities.
- The contract is a matching Ubuntu 24.04 baseline, not every Debian derivative
  or an arbitrary partially upgraded host.
- Sigstore verification happens on a connected trusted workstation before the
  air gap. Inside the isolated environment, the internal manifest detects damage
  but does not independently create a new trust root.
