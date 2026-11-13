# Own each ACME attempt in a bounded process

Status: accepted

## Context

Lego's pinned Obtain API has no context parameter. Certificate polling timeouts
do not cover the entire order, registration, provider calls and DNS propagation
sleeps. The former context-select wrapper returned while its Obtain goroutine
could keep ordering. The parent then stopped refreshing the claim and restored
DNS environment, so another attempt could overlap live SDK work.

A regression using the real Lego client and a local HTTPS CA endpoint proves
the former wrapper returned on cancellation while its order request remained
open. Waiting synchronously alone would avoid abandoned work but could not
enforce the worker's claim/deadline policy for a noncooperative provider wait.

## Options

- Keep the context-select wrapper: leaves live SDK work after ownership ends.
- Join synchronously in the parent: cannot bound noncancelable provider waits.
- Bind only the ACME HTTP transport to context: does not cancel DNS propagation
  sleeps, provider SDK calls or every cleanup path.
- Own an isolated child of the existing binary: supplies a hard boundary for
  the complete attempt without a new host runtime or privileged service.

## Decision

The existing worker invokes its own installed binary with the private
`--issue-certificate-child` entrypoint for each attempt. The child entry is
handled before database/worker startup and inherits the worker's unprivileged
identity and systemd sandbox. No new service, public API, executable, TCP
listener or host runtime is introduced.
The broker's executable identity policy still denies acmed and its child all
privileged host-management opcodes.

Database DSN and management JWT/static-token environment keys are removed,
including case aliases. The child does not use PostgreSQL. An older binary
that ignores the private argument therefore fails its required-DSN startup
check instead of becoming another worker during a rolling replacement.

One newline-delimited JSON request on stdin carries only options/paths, at most
64 KiB excluding LF. The parent keeps its writer open through process Wait;
the child monitors EOF/read failure/extra input and exits on loss of that owner.
This works on Windows and Unix without PID polling or platform-specific
parent-death races. It also closes real SDK connections if the parent is killed
before its normal cancellation/cleanup runs. DNS secrets
are read and applied only inside that child. Its private stdout result includes
the PEM material that Lego's Resource JSON normally omits. Capture is capped
at 4 MiB; raw stdout/stderr is never copied into errors/journal. SDK verbose
stderr is discarded, while a bounded final SDK error uses the existing
failed-row/audit path. Success requires a complete protocol result, zero process
exit and a valid matching certificate/key pair. Duplicate/noncanonical fields,
null values, invalid UTF-8, unknown fields, excessive nesting and trailing data
are rejected; no partial response is promoted.

The parent uses CommandContext and the shared commandprocess policy: owned
process group cancellation/cleanup on Linux/macOS, native process cancellation
on Windows and two-second inherited pipe waits. It waits/reaps before stopping
and joining the claim heartbeat, then retains the existing store/file/apply
path. It never falls back to in-parent SDK execution.

The request deadline is capped at 45 minutes. The child enforces it with a hard
process-exit timer independently of both the parent and the owner pipe. The
deadline is earlier than the one-hour
stale-claim interval. The first service TERM is ignored by the active child,
matching the parent worker's graceful issuance policy; default handling is
restored for a second signal. The existing 50-minute systemd stop allowance
and final cgroup cleanup remain unchanged. Parent deadline cancellation still
uses immediate process termination, independent of that graceful signal.

## Consequences and verification limits

Provider variables and SDK background work cannot leak into the next attempt
through the long-lived worker. Normal completion lets SDK cleanup finish before
the child exits. Forced termination can leave an external CA order, TXT record
or HTTP-01 token indeterminate; failure/backoff must not claim no issuance or
successful cleanup. Operators may need to inspect/remove stale challenges.
No protocol can roll back an already accepted remote order by killing a client.

Tests exercise real child processes, a real Lego HTTPS request, parent
cancellation and forced parent death, child self-deadline with a noncancelable wait, first/second Unix
signals, environment isolation, result integrity, output/request limits and
privacy. They do not prove public CA/provider cleanup or full appliance
acceptance. Crash consistency between DB commit, PEM promotion and the pending
apply marker remains separate work.

Rollback: revert this change; no new service or database migration is involved.
