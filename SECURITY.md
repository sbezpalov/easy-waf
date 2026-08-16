# Security Policy

Easy Home WAF sits on the edge of somebody's network and holds their TLS keys, so
a vulnerability here is not academic. This document is about **reporting** one.
For hardening and operating guidance, see [docs/SECURITY.md](docs/SECURITY.md).

## Supported versions

| Version | Supported |
|---------|-----------|
| latest release (see [`VERSION`](VERSION)) | security fixes |
| previous minor | critical fixes only, best effort |
| older | no |

This is a small project. "Supported" means a fix will be written and released,
not that a response time is contractually guaranteed — see below for what is
realistic.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private reporting: **Security → Advisories → Report a vulnerability**
on this repository. That creates a private thread visible only to maintainers and
lets the fix and the advisory be prepared together.

If private advisories are unavailable to you, email the address in the repository
owner's GitHub profile with `easy-waf security` in the subject.

### What to include

The faster a report can be reproduced, the faster it is fixed:

- affected version (`VERSION` or the release tag) and platform;
- component: management API/UI, `easy-waf-hostd` broker, HAProxy rendering, ACME,
  installer scripts;
- what an attacker needs to start — unauthenticated network access, an operator
  session, a local account on the appliance, a compromised `easy-waf-api`;
- reproduction steps, a request/response pair, or a configuration that triggers it;
- impact as you see it.

A proof of concept is welcome but never required. A clear description of the
faulty logic is worth more than an exploit.

### What to expect

- **Acknowledgement:** within 5 working days.
- **First assessment** (severity, whether it reproduces): within 10 working days.
- **Fix:** severity-dependent. A privilege-escalation or unauthenticated-access
  issue is prioritised above everything else in the backlog.
- **Disclosure:** coordinated. The advisory is published together with the release
  that fixes it, crediting the reporter unless they prefer otherwise.

If a report turns out to be a configuration mistake rather than a vulnerability,
you will get a written explanation of why — not silence.

## Scope

In scope, roughly in order of how seriously it is taken:

1. **Privilege escalation from `easy-waf-api` to root** through the
   `easy-waf-hostd` broker — the broker is the trust boundary of this design and
   it explicitly assumes the API can be compromised.
2. **Authentication and session handling** of the management API: bypass, token
   forgery, missing revocation, enrollment abuse.
3. **HAProxy configuration injection** — any stored value that can add or alter a
   directive in the generated configuration.
4. **SSRF / request forgery** through external blocklist feeds, the CrowdSec LAPI
   client, ACME DNS providers, or GeoIP.
5. **Supply chain**: release artifact verification, installer behaviour.
6. Information disclosure of secrets: keys, tokens, database credentials in logs,
   diagnostics bundles, or API responses.

Out of scope:

- Attacks that require an operator to already have a valid management session and
  only affect that operator's own appliance. The management API is a full-control
  interface by design.
- Findings that depend on running the management interface exposed to the
  internet without a VPN or reverse proxy — [documented as unsupported](docs/SECURITY.md).
- Denial of service by simply sending a lot of traffic to the edge; that is what
  the rate limiting and CrowdSec integration are for, and tuning is deployment-specific.
- Vulnerabilities in HAProxy, CrowdSec, PostgreSQL or Ubuntu itself. Report those
  upstream; if easy-waf's defaults make an upstream issue worse, that part is in scope.
- Missing hardening headers or TLS options on the **edge** vhosts that the operator
  controls through per-application settings.

## Security design, in one paragraph

`easy-waf-api` runs unprivileged as `easy-waf` with `NoNewPrivileges` and
`ProtectSystem=strict`. Every privileged host operation goes through
`easy-waf-hostd`, a root broker on a unix socket that authenticates its peer with
`SO_PEERCRED`, dispatches only allowlisted opcodes, and re-validates arguments
itself rather than trusting the caller. There is no shared default password: the
first operator enrolls with a one-time CSPRNG secret readable only on the local
console. Release artifacts are verified against `SHA256SUMS` before installation.
The details — and the reasoning behind each choice — are in
[docs/SECURITY.md](docs/SECURITY.md).

## Credit

Reporters are credited in the release notes and the advisory. If you would rather
stay anonymous, say so in the report.
