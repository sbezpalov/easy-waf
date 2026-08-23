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

The TLS requirement there is doing two jobs, and only one of them is
confidentiality. Loopback makes it obvious which appliance is being addressed;
off loopback it stops being obvious, and an assistant that manages more than one
box needs to know it is talking to the right one — a stale DNS record or a
mistyped port otherwise sends "unblock 1.2.3.4" to somebody else's edge. Clients
should pin the appliance's management certificate, not merely accept it.

**Its own credential, with a floor.** `EASY_WAF_MCP_TOKEN`, minimum 32
characters, refused below that — the same fail-closed rule as
`EASY_WAF_JWT_SECRET` and `EASY_WAF_ADMIN_TOKEN`, and for the same reason. It is
not an operator session: revoking it does not sign anybody out, and signing out
does not revoke it. The token authenticates the *server*; it does not grant the
caller anything the API would not grant the corresponding operator.

One shared secret means one implicit identity — "somebody holding the token".
That is honest for a single appliance with a single caller, and it is the first
thing that breaks with a second one. See the open questions: the decision is
deferred, but the audit schema below is shaped so that deferring it stays cheap.

**Read-only by default; no mutating verb executes on its own authority.** Two
tiers, and the boundary is the whole point:

| Tier | Verbs | Gate |
|------|-------|------|
| **Diagnostics** (read-only) | `status`, `doctor`, `list_applications`, `describe_application`, `haproxy_check`, `config_revisions`, `certificate_expiry`, `geoip_status`, `why_blocked` (correlate an address across IPBL, GeoIP, CrowdSec and Fail2Ban), `recent_events`, `journal_tail` | on when the server runs |
| **Management** (mutating) | `apply`, `rollback_to_revision`, `set_application_enabled`, `blocklist_add` / `blocklist_remove`, `allowlist_add` / `allowlist_remove`, `issue_certificate`, `reload_haproxy` | `EASY_WAF_MCP_ALLOW_MUTATION=1` **and** per-action human confirmation |

`why_blocked` is the verb that justifies the whole exercise: today it is four
lookups and a correlation the operator does in their head.

**Mutating verbs propose; a human confirms the specific change.** A call to
`apply` does not apply. It returns a **pending change** — an ID, a rendered diff,
and the revision the diff was computed against — and nothing happens until the
operator confirms that ID in the UI or from the console.

This is the answer to prompt injection, and it is worth being precise about why
the two obvious alternatives are not.

- A static `EASY_WAF_MCP_ALLOW_MUTATION=1` is **ambient authority**: set once,
  forgotten, and every later tool call rides on it.
- A short-lived confirmation token minted in the UI only narrows the window. The
  operator mints it exactly when the agent is about to do work — which is exactly
  when the agent is processing the untrusted text that carries the injection. It
  also has a failure mode of its own: if confirming is tedious, operators mint
  long-lived tokens or leave the flag on, and the control is back to ambient
  authority with extra steps. Controls that irritate get routed around.

Binding the permission to a *specific diff* instead of to an interval is what
actually closes it. Injected text can make the agent propose anything, which is
harmless and, more to the point, visible. It cannot make the change happen,
because happening requires a human who has read the diff.

The shape is not new here: `firewall/apply-rollback` + `commit` and the revision
history are already "act and confirm separately". This extends an existing idea
to a new surface rather than inventing one.

Two details this does not work without:

- **The confirmation is bound to the state the diff was computed against.**
  Otherwise it is a TOCTOU: the agent proposes against revision A, the operator
  reads the diff of A, state moves to B, and confirm applies to B. A pending
  change carries the revision it was built on and is refused if state has moved.
- **Pending changes expire** (15 minutes) and are single-use, which also supplies
  idempotency: repeated identical calls return the same pending ID rather than
  stacking.

`EASY_WAF_MCP_ALLOW_MUTATION` stays, but as a **kill switch, not an
authorization**: off means the mutating verbs are not registered in the tool
registry at all. That is worth having independently of confirmation.

Cost note, since the first draft of this record got it wrong: the confirmation
token and propose/confirm cost about the same to build — both need UI, storage
and a revocation or expiry path. Propose/confirm is not the expensive option, it
is the one that works.

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

**`journal_tail` stays, redacted.** It is the one read-only verb that can return
a secret an operator pasted into a log line, so it reuses the masking the
diagnostics bundle already applies (`CROWDSEC_LAPI_KEY`, `EASY_WAF_JWT_SECRET`,
`EASY_WAF_ADMIN_TOKEN` — see [DIAGNOSTICS.md](../DIAGNOSTICS.md)) and caps the
number of lines returned. Dropping it would remove most of the diagnostic value;
masking is the same trade the bundle already makes.

**Read-only is safer, not safe, and the record should not pretend otherwise.**
`why_blocked`, `recent_events` and `journal_tail` pull attacker-influenced text —
a User-Agent, a request path, a log line — into the agent's context. That is the
injection *vector*, and it exists at the diagnostics tier too. It cannot be
removed without removing the verbs that make this worth building. What can be
removed is the payoff, which is what propose/confirm does.

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
- Prompt injection is not solved, only defanged. The agent still reads
  attacker-influenced text, and propose/confirm removes the payoff rather than
  the vector. An operator who confirms without reading the diff has opted back
  into the original problem, and no design here can stop that.
- Confirmation is friction in exactly the moment somebody wants speed — during an
  incident. That is the cost being accepted, and it is the reason the diagnostics
  tier has to be genuinely useful on its own: most of the value should arrive
  without anyone confirming anything.
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
3. Audit actor as a **pair**: kind (`operator` / `automation` / `mcp`) *and* a
   name. A migration, and the one piece that touches existing code — which is
   exactly why the name goes in now. Today it is a constant; the day there is a
   second caller it is a column that already exists rather than a second
   migration against a live appliance. Half an hour now, a change window later.
4. Pending changes: storage with a 15-minute expiry, the revision the diff was
   built against, a confirm endpoint, and the UI surface that shows a diff and
   confirms it. This is the prerequisite for step 5, not a follow-up to it.
5. Mutation tier behind `EASY_WAF_MCP_ALLOW_MUTATION=1`, starting with `apply`
   and `rollback_to_revision`. **Do not ship an interim static-flag version**: a
   temporary ambient-authority design is the kind that becomes permanent, and
   there would be no forcing function to replace it once it works.
6. `packaging/systemd/easy-waf-mcpd.service` (not enabled), nfpm contents,
   `docs/MCP.md`, and a `scripts/smoke-appliance.sh` check that the listener is
   absent unless configured.
7. Review gate: the tool registry gets the same review standard as the broker's
   opcode switch. A new verb is a new privilege.

## Open questions

Both are deferred deliberately, and both have a trigger. An open question with no
trigger is just an unfinished sentence — it gets revisited when somebody
remembers it rather than when the situation calls for it.

### Per-verb scopes versus flat tiers

Should the token carry a capability list, so different callers get different
verbs, instead of the two tiers here?

The case for is ordinary least privilege: a monitoring assistant that only needs
`status` and `doctor` should not hold a credential that can also touch the block
lists.

The case against is that **per-action confirmation has already absorbed most of
what scopes would buy on the mutating side.** Once a human approves each diff,
"which mutating verbs may this token *propose*" is a question about noise, not
about damage — a proposal is not an action.

Where scopes would genuinely earn their place is the opposite end from where the
instinct points: *inside diagnostics*, which has no confirmation gate and is
where information disclosure lives. `journal_tail` is categorically more
sensitive than `status`.

So the cheaper answer, if that need appears, is not a capability system but a
**third flat tier — "sensitive reads"** (`journal_tail`, `recent_events` with
request detail, anything returning raw attacker-controlled text), off by default.
One more switch of a shape that already exists, against a capability list that
needs a schema, a minting UI, validation, and a decision for every new verb about
whether existing tokens include it. That last one is the trap: it is a decision
made repeatedly, quietly, and under time pressure.

General scopes also have a presentation problem. A token narrowed to nine verbs
out of eleven *feels* controlled, while the two that remain may be the entire
attack surface. Tiers are coarser and harder to fool yourself with.

**Trigger:** a second caller at a different level of trust, or the first
complaint that `journal_tail` is visible to something it should not be.

### Identity of the caller

`EASY_WAF_MCP_TOKEN` is one shared secret and therefore one implicit identity.
Three things break it: a second client (laptop plus schedule plus a second
person), a second appliance under one assistant, and any fleet arrangement —
which is not hypothetical for anyone running this at more than one site.

The options, by cost:

- **Named tokens.** A table of `(name, hash, created, last used, revoked)`. Still
  bearer, still shared secrets, but you know *which* one was used, you can revoke
  one, and the audit record gains a caller. Roughly 80% of the value for very
  little work.
- **mTLS.** A client certificate per caller. Cleaner in principle; issuance and
  rotation are real operational weight for a home appliance, and client-cert
  support across MCP clients is uneven.
- **OAuth with dynamic client registration.** Where the specification is heading
  for HTTP transports, and the right long-run answer if third-party clients ever
  connect. Premature now: the spec is still moving, and pinning to it early buys
  a migration.

Not deciding is fine. What is not fine is letting the *audit schema* assume a
single caller, which is why the implementation sketch above makes the actor a
(kind, name) pair from the start. That is the cheap insurance in the one place
where retrofitting is expensive.

**Trigger:** a second caller, a second appliance, or any non-loopback bind.
