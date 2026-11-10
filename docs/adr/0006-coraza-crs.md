# ADR 0006 — What kind of WAF this project is

- **Status:** proposed
- **Date:** 2026-11-10
- **Deciders:** repository maintainer
- **Context version:** 1.6.0
- **Implementation:** none. No Coraza process, no CRS ruleset, no body buffer
  beyond the header limits that already exist.

## Context

The name says WAF. What ships is a reverse proxy with edge controls: TLS,
per-application rate limits, path and header rules, GeoIP, IP lists, and
CrowdSec decisions over SPOE. Those controls read the request line and
headers. They do not read the body. The project already says this in the
README, because an exploit delivered in a body passes them.

Coraza is an Apache-2.0 Web Application Firewall library, and coraza-spoa is a
SPOE agent that can apply the OWASP Core Rule Set in front of HAProxy. That
would be the first component here that inspects bodies. It is also a second
process on the request path, with its own failure mode, CPU cost, and false
positives. CRS is loud on Home Assistant, Nextcloud, and anything that posts
JSON or uploads files.

## Options considered

### A. Stay an edge and a reverse proxy

Keep the current controls. Keep saying, in the name and the docs, that bodies
are not inspected. No new process. A buyer who wants CRS does not get it from
this project.

### B. CRS on for every application

Maximum signature coverage, maximum false positives, and a body buffered for
every request including the ones that are websockets or large uploads. A
mistake in the ruleset is an outage. This fights the "plug in a homelab
service" goal.

### C. Optional Coraza/CRS via coraza-spoa, off unless an application asks — *recommended if this is accepted*

The product remains an edge and a reverse proxy. Coraza is an optional SPOE
sidecar, Apache-2.0, not vendored into this repository. An application turns
it on. The default stays off, so today's golden configs do not grow a body
buffer.

Failure mode, if it is built: **fail open for the sidecar being down, fail
closed for a rule that matches.** That matches CrowdSec in this codebase: a
missing bouncer does not black-hole the house, and a positive decision still
denies. The difference from CrowdSec is that a positive CRS match is a
signature, not an IP reputation, and it will be wrong more often. The UI has
to show the rule id that fired.

Body policy stays what it is now (size and multipart, from headers) even when
Coraza is off. Turning Coraza on does not raise those limits.

Resource bound: the sidecar gets its own timeout, shorter than the backend
timeout, and a maximum body it will buffer. Anything larger is not inspected
and is rejected or passed under the application's existing body limit — that
choice is part of accepting this record, and the recommendation is to reject
(413) rather than to skip inspection and pass a body the operator thought was
scanned.

## Decision

Do not add Coraza in this change. The positioning is option C's first sentence,
already true without the sidecar: **Easy Home WAF is a hardened edge and
reverse proxy.** A signature engine is optional later work, not the thing a
default install runs. Option B is rejected. Option A remains acceptable if the
maintainer would rather never take the false positives.

## Consequences

- Docs and the README should keep the sentence that bodies are not inspected,
  until an accepted follow-up actually ships the sidecar.
- If the sidecar is built later, CRS paranoia level starts at the lowest that
  still loads, per application, not at the strictest upstream default.
- GeoLite2's license problem does not apply: Coraza and CRS are Apache-2.0.
  The rule files still should be pinned and updated on purpose, not fetched
  from the network on every request.
