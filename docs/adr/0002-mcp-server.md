# ADR 0002 — An MCP server for management and diagnostic verbs

- **Status:** proposed
- **Date:** 2026-08-16
- **Deciders:** repository maintainer
- **Context version:** 1.4.0
- **Implementation:** none yet — this record exists so the design is settled
  before any code opens a second way into the control plane.

## Context

Operating this appliance means moving between a web UI, `curl` against the REST
API, `easy-waf-admin` on the console and `journalctl`. Most of what an operator
actually does in a session is a small set of verbs: *what is the state*, *why is
this host being blocked*, *apply*, *roll back*, *unblock this address*, *is the
certificate about to expire*. Those are exactly the shape of an
[MCP](https://modelcontextprotocol.io/) tool surface, and an assistant that can
call them turns "read four screens and correlate" into one question.

The pull is real, and so is the risk. This is a WAF that terminates TLS at the
edge of somebody's network. Its whole design premise is stated in
[docs/SECURITY.md](../SECURITY.md): `easy-waf-api` is assumed compromisable, and
`easy-waf-hostd` re-validates everything rather than trusting it. An MCP server
is a **second control-plane entry point** — a new listener, a new authentication
path, a new authorization surface — and adding one carelessly would undo the
property that the rest of the appliance is built around.

Two failure modes are worth naming before the options, because they decide the
design:

- **A second path into the store.** If the MCP server talked to PostgreSQL or to
  `internal/engine` directly, every validator that lives in the API handler would
  be bypassable through it, and the render-safety checks would become the only
  thing standing between a tool call and a generated HAProxy configuration. The
  project already learned this lesson twice: 1.2.1 moved application-field
  validation into the renderer *because* handler-side checks are advisory, and
  1.4.0 found three more fields that had been left behind (see the CHANGELOG).
  A second client of the store would re-create that class of bug wholesale.
- **A confused deputy with an ambient token.** An MCP server holding a
  long-lived credential and accepting instructions derived from untrusted text —
  a log line, a User-Agent string, an issue body pasted into the conversation —
  is a prompt-injection target whose payoff is "unblock my IP" or "disable the
  WAF on this host". Read-only verbs make this an information-disclosure problem;
  mutating verbs make it an integrity problem.

## Options considered

### A. No MCP server

Zero new surface. Keeps the appliance operable only by hand. Defensible, and the
right answer if the design below cannot be made safe — but it declines a genuine
operational gain for a young project whose main cost is the operator's attention.

### B. MCP routes inside `easy-waf-api`, on the existing management listener

Cheapest to build: one more route group behind the existing session middleware,
management ACL and TLS. No new port, no new binary, no new authentication path.

But it inherits the session model, which is built for a browser: JWTs with a
24-hour TTL and `session_version` revocation. An agent is not a browser — it
wants a credential that is not somebody's login, that can be scoped, and that can
be revoked without signing the operator out everywhere. It also makes "turn MCP
off entirely" a build-time or route-level decision rather than "do not start that
listener".

### C. A separate `easy-waf-mcpd` process on its own port — *recommended*

A small binary with its own systemd unit and its own listener, which **calls the
REST API over loopback as an ordinary client**. It holds a dedicated credential,
speaks MCP over streamable HTTP, and owns no database handle, no state directory
and no privileged socket.

The property that makes this the right shape: there is still exactly **one**
authorization path and **one** set of validators. An MCP tool call becomes an
HTTP request against the same endpoint a human's browser would hit, subject to
the same checks, the same rate limits and the same audit trail. The MCP server
is a translator, not a peer.

Cost: another unit to install, start, monitor and document; another credential to
manage; and a hop that makes some errors read as "the API said 400" rather than
naming the field. All of that is visible and boring, which is the trade to want.

### D. MCP over stdio, no listener at all

The transport most MCP servers use: the client spawns the process and talks over
pipes. No port, no network authentication, no listener to firewall — strictly the
smallest attack surface of any option here.

It also requires the agent to be on the appliance, or to have SSH to it, which
for a headless box on someone's LAN means the operator's laptop cannot use it
without a shell session. This does not fit the way the rest of the product is
reached (a browser pointed at `:8443`). Worth keeping as a **second transport**
for local use, not as the primary one — the verb layer is identical either way.

## Decision

**Adopt C**, with D available as a build flag for local use, and with the
following constraints as part of the decision rather than as implementation
detail:

**Process and transport.** A separate binary `easy-waf-mcpd`, its own unit,
running as the unprivileged `easy-waf` user with the same hardening as
`easy-waf-api` (`NoNewPrivileges`, `ProtectSystem=strict`, no `ProtectHome`
exception — it never touches `/home`). MCP over streamable HTTP. Bind
**`127.0.0.1:8446`** by default; the port is otherwise unused
(80/443 edge, 8000 legacy management HTTP, 8089 ACME loopback, 8080 CrowdSec
LAPI, 8443 management HTTPS). Pin the MCP specification revision in the code and
name it in `docs/`; the protocol is young and "latest" is not a version.

**It is off unless switched on.** No unit enabled by default, no listener without
`EASY_WAF_MCP_LISTEN` set. An appliance that never opts in must be
byte-for-byte the appliance it is today.

**Never on the edge, loopback by default.** A non-loopback bind requires
`EASY_WAF_MCP_ALLOW_NONLOOPBACK=1` and TLS, refuses to start without both, and is
covered by the same `management_allowed_cidrs` policy and nftables rules as the
management API. Remote use is expected to go through the VPN or SSH forward that
[docs/SECURITY.md](../SECURITY.md) already assumes for `:8443`.

**Its own credential, with a floor.** `EASY_WAF_MCP_TOKEN`, minimum 32
characters, refused below that — the same fail-closed rule as
`EASY_WAF_JWT_SECRET` and `EASY_WAF_ADMIN_TOKEN`, and for the same reason. It is
not an operator session: revoking it does not sign anybody out, and signing out
does not revoke it. The token authenticates the *server*; it does not grant the
caller anything the API would not grant the corresponding operator.

**Read-only by default, mutation is a separate switch.** Two tiers, and the
boundary is the whole point:

| Tier | Verbs | Gate |
|------|-------|------|
| **Diagnostics** (read-only) | `status`, `doctor`, `list_applications`, `describe_application`, `haproxy_check`, `config_revisions`, `certificate_expiry`, `geoip_status`, `why_blocked` (correlate an address across IPBL, GeoIP, CrowdSec and Fail2Ban), `recent_events`, `journal_tail` | on when the server runs |
| **Management** (mutating) | `apply`, `rollback_to_revision`, `set_application_enabled`, `blocklist_add` / `blocklist_remove`, `allowlist_add` / `allowlist_remove`, `issue_certificate`, `reload_haproxy` | `EASY_WAF_MCP_ALLOW_MUTATION=1` |

`why_blocked` is the verb that justifies the whole exercise: today it is four
lookups and a correlation the operator does in their head.

**Verbs that are never exposed, at any tier.** Anything that reaches
`easy-waf-hostd`: netplan, nftables, systemd unit control, package upgrades,
local accounts, SSH keys. The broker exists because the API is assumed
compromised; putting a language model in front of it inverts that reasoning.
Also excluded: reading secrets, enrollment, password change, and settings that
change the management listener or ACL — an agent must not be able to alter the
path by which a human would take control back.

**Everything is audited as a distinct actor.** Existing audit records gain an
actor kind so `mcp` is distinguishable from `operator` and `automation` after the
fact. Mutating verbs additionally record the tool name and arguments. An operator
must be able to answer "did the assistant do this?" without inference.

**Destructive verbs carry an idempotency key and echo a diff.** `apply` and
`rollback_to_revision` return what changed *before* the change is committed where
the API allows it, so the calling agent can surface it. Repeated identical calls
must not stack.

## Consequences

Positive:

- One authorization path. The MCP surface cannot outgrow what the REST API
  permits, because it has no other way in.
- The kill switch is a unit, not a code change: `systemctl stop easy-waf-mcpd`.
- `why_blocked` and `doctor` alone remove most of the log-correlation work from a
  routine incident on this appliance.
- Read-only default means the first version is an information-disclosure risk at
  worst, which is a proportionate place to start.

Negative / accepted cost:

- A third long-running process, with its own unit, log stream, failure mode and
  documentation. On an appliance sized at 2 vCPU / 2 GB that is not free.
- A new credential in `easy-waf.env`, which is already the file most likely to be
  mishandled.
- Prompt injection stays a live risk for the mutating tier however carefully the
  verbs are scoped. Read-only is genuinely safer here; "read-only by default" is
  a real control, not a formality.
- Latency and error fidelity: the extra hop makes some failures read as an HTTP
  status rather than as the underlying reason. Verb implementations should
  unwrap the API error, not pass it through.
- MCP itself is moving. A pinned revision means a deliberate upgrade step, and
  the surface will need re-reviewing when it moves.

## Implementation sketch

1. `cmd/easy-waf-mcpd` + `internal/mcp`: transport, tool registry, and a thin
   REST client that carries the token and nothing else.
2. Diagnostics tier only, behind `EASY_WAF_MCP_LISTEN`, loopback, no mutation
   path compiled in reach of the registry.
3. Audit actor kind (`operator` / `automation` / `mcp`) — a migration, and the
   one piece that touches existing code.
4. Mutation tier behind `EASY_WAF_MCP_ALLOW_MUTATION=1`, starting with `apply`
   and `rollback_to_revision`, each with an idempotency key.
5. `packaging/systemd/easy-waf-mcpd.service` (not enabled), nfpm contents,
   `docs/MCP.md`, and a `scripts/smoke-appliance.sh` check that the listener is
   absent unless configured.
6. Review gate: the tool registry gets the same review standard as the broker's
   opcode switch. A new verb is a new privilege.

## Open questions

- Should the mutating tier require a **human confirmation token** minted in the
  UI and valid for minutes, rather than a static env switch? That is the design
  that actually answers prompt injection, and it is more work.
- Does `journal_tail` belong in diagnostics at all? It is the one read-only verb
  that can return secrets an operator pasted into a log line.
- Per-verb scoping in the token (a capability list) versus the two flat tiers
  here. Tiers are simpler to reason about and simpler to get wrong in the safe
  direction; scopes are more precise and more to maintain.
- Whether a second appliance-to-appliance use case exists, which would change the
  authentication story from "one token" to something with identity.
