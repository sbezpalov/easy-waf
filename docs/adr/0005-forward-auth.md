# ADR 0005 — Forward authentication in front of a published application

- **Status:** proposed
- **Date:** 2026-11-10
- **Deciders:** repository maintainer
- **Context version:** 1.6.0
- **Implementation:** none. Published applications are not sent to Authelia,
  Authentik, or any other login service.

## Context

Some applications have no login of their own, or a login the operator does not
trust on the open internet. Authelia and Authentik already solve "who is this
person" for a homelab. HAProxy can ask one of them before it picks a backend.

That is a new dependency on the request path. Today a published app is
protected by the edge (TLS, rate limit, CrowdSec, GeoIP, path rules) and by
whatever the backend does. An auth service in the middle changes the failure
mode: if it is down, either every visitor is rejected or every visitor is
treated as anonymous.

The management panel is not part of this question. It stays a local account.
Putting the panel behind the same forward-auth service would make the service
that is being administered a dependency of the administrator.

## Options considered

### A. No forward auth

Applications keep their own logins. Nothing on the request path can fail
closed because an identity provider is down. Apps without a login stay open
to anyone who can reach the hostname.

### B. Forward auth, fail open

If the auth service does not answer, HAProxy sends the request to the backend.
The site stays up. A down Authelia is then a bypass, which is the opposite of
why the operator turned the feature on.

### C. Forward auth per application, fail closed — *recommended if this is accepted*

An application opts in. HAProxy asks the configured auth endpoint
(`http-request auth` or a subrequest, whichever HAProxy 2.8 actually
implements without a Lua detour) and denies with 401 or 302 when the answer
is missing, slow, or not an allow. The timeout is short and bounded. Other
applications on the same frontend are unchanged. The management listener is
unchanged.

The auth service is not run by this project. The operator runs Authelia or
Authentik on the LAN and points the application at it. Secrets for that
service stay in that service. The generated config may contain a URL. It must
not contain a long-lived shared secret in the clear; if a header has to be
sent, it is read from a file the way other edge secrets are, not pasted into
`haproxy.cfg` as a literal.

## Decision

Do not implement this until the record is accepted. If it is accepted, the
failure mode is **closed**: a silent auth service is a denial, not an
anonymous pass. Fail open is rejected. The panel is out of scope.

## Consequences

- An opted-in application is down when its auth service is down. That is the
  trade the operator is making, and the UI has to say so before the toggle is
  saved.
- A bug that marks every app as opted-in would take the edge down. The default
  stays off, and render must treat a missing URL as "not configured" rather
  than as "deny the world".
- This does not inspect bodies and does not replace the backend's own session.
