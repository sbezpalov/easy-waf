# ADR 0003 — A Docker image that is only the edge

- **Status:** proposed
- **Date:** 2026-11-10
- **Deciders:** repository maintainer
- **Context version:** 1.6.0
- **Implementation:** none. This record is the decision to make before any
  Dockerfile is added.

## Context

The supported product is an Ubuntu 24.04 appliance. `easy-waf-api` is assumed
compromisable, and `easy-waf-hostd` is the only process that may change the
host: nftables, netplan, apt, accounts, power. That split is the point of the
current architecture.

People still ask for a container. A container that also tries to manage the
host needs to be privileged, to mount the host's nftables and systemd, and to
talk to a root broker that was written for a VM it owns. That is a second
privilege model, and it throws away the reason hostd exists.

## Options considered

### A. No container

The appliance stays the only install path. Nothing new to secure. People who
will not run a VM do not get the product.

### B. Privileged container that runs hostd

One image, the full panel, including firewall and package upgrades. It needs
`--privileged` or a long capability and bind-mount list, and a mistake is root
on the host. The threat model ("the API can be compromised, the broker
re-checks") gets harder to explain when both processes share a container
namespace with the host's network stack.

### C. An edge-only image, with host management absent — *recommended, not yet adopted*

The image runs `easy-waf-api`, `easy-waf-acmed` and HAProxy. It does not run
`easy-waf-hostd`. The panel's host screens (network, nftables, apt, users,
power, Fail2Ban's host socket) are off because the broker is not there, not
because the API hides buttons and still has the code path.

Published ports are 80 and 443. The management listener stays on loopback
inside the container unless the operator publishes it. State (PostgreSQL may
be another container, certificates, HAProxy config) is a volume. There is no
nftables integration and no claim that the container replaces the host
firewall. CrowdSec is optional and only as a SPOE sidecar the operator runs;
this image does not install it.

Capabilities: `NET_BIND_SERVICE` if the process binds 80 and 443 as non-root,
or the orchestrator publishes those ports onto unprivileged high ports. No
`SYS_ADMIN`, no host PID namespace, no Docker socket.

## Decision

Do not build the image until this record is accepted. If it is accepted, build
**C** and not B. The Ubuntu package remains the product this project tells
people to install. The container is a way to run the proxy, not a way to
administer a machine.

## Consequences

- Operators who want the firewall rollback and the host panel still use the
  appliance. The container will not grow those features later without a new
  record: that would be option B.
- Documentation has to say the container does not set `trusted_proxies`,
  nftables or GeoIP databases for you. GeoLite2 stays out of the image.
- Fail-open and fail-closed do not change for HAProxy itself. What changes is
  the absence of host policy: a compromised API in the container can change
  the generated proxy config and the volume, and cannot change the host
  firewall because it has no broker and no privilege to do so.
