# APT ownership outside the management broker

Status: accepted

## Context

APT/dpkg can outlive a panel connection. Process groups and detached Go contexts
protect against cancellation of that connection, but do not escape systemd's
service cgroup. Restarting the management broker previously killed its package
transaction. Deferring package-initiated broker restart solves self-upgrade;
it cannot protect a transaction from an independent broker restart or crash.

The real systemd regression reproduces this failure with the preceding binary.
The replacement must retain the selected operation, its output and actual exit
result across broker stop/start and SIGKILL without granting the API another
privileged channel.

## Options

- Keep APT in broker and weaken broker KillMode: leaves unrelated privileged
  commands outside normal service cleanup and still loses its observation state.
- Launch a detached child/nohup/process group: remains in the broker cgroup.
- Create a transient systemd job per request: possible, but requires a new durable
  launch/result protocol, including recovery in the gap before PID publication.
- Keep the existing bounded executor/action manager in a separate, private APT
  service: preserves the current operation model while separating its lifecycle.

## Decision

`easy-waf-apt.service` runs the existing binary as `easy-waf-hostd apt-worker`.
It owns APT children, single-flight state, run IDs, retained results and logs.
Broker forwards exactly the existing APT JSON/NDJSON opcodes; public HTTP routes
and confirmations remain unchanged. There is no broker-local execution fallback.

The service exposes only `/run/easy-waf-apt/worker.sock`: root-owned mode 0600
inside a root-only runtime directory of mode 0700. Both ends verify root SO_PEERCRED.
Worker also rejects every non-APT opcode. The genuine API UID/executable accepted
by the public broker is denied direct worker access even when the filesystem
barrier is deliberately removed in the isolated test.

Broker Wants/After the worker; worker signals readiness after its socket is
usable. There is no PartOf/BindsTo coupling. Broker keeps its normal cgroup kill
policy. Worker TERM closes listeners/observers and joins package work instead
of canceling it, including synchronous mutations. KillMode=mixed and a 32 minute
stop allowance cover the executor's 30 minute command budget and cleanup.
No new TCP listener, binary, public service-control verb or host runtime is added.

Self-upgrade must replace both processes. The independent maintenance helper
takes the root-only internal execution lease before the real APT frontend and
dpkg backend POSIX locks; it holds all three across active-only worker/broker
restart. Worker takes the internal lease before launching each mutating APT.
This prevents a new transaction entering while maintenance restarts its owner.
The internal flock file is separate from dpkg's record-lock files, never
truncated/unlinked, opened beneath the private state-directory descriptor and
checked for safe ownership, permissions, link count and identity after waiting.
The old broker transition still coordinates through the real package locks.

Needrestart leaves the four managed static Go processes to this package.
Removal queues worker stop without waiting inside dpkg; the owner finishes its
own removal transaction before exiting. ACME's long graceful stop is also queued.

## Consequences and limits

Restarting/crashing broker no longer interrupts APT or replaces its run ID/result.
Unavailable worker produces an explicit error rather than a duplicate/local run.
Forwarding retains bounded memory, per-write deadlines and the existing overall
operation lifetime. The worker is an additional internal root service to monitor.

Worker failure, SIGKILL, power loss and full host reboot remain distinct from
broker restart. Restarting the worker can lose its last in-memory result; saved
process metadata is treated conservatively and logs remain available. This does
not turn APT into a crash-proof package manager or prove full appliance/ACME/WAN
acceptance. The 30 minute execution deadline still applies.

Tests cover an owner-cgroup negative control, broker stop/SIGKILL with stable
operation/result, self-upgrade exclusion, real API-vs-root peer authentication,
stopped services, graceful removal of the running worker package, proxy failure
without fallback, lease contention/cancellation/unsafe paths and synchronous drain.
