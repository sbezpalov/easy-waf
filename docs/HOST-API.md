# Host management API (Ubuntu)

Authenticated routes under **`/api/v1/host/*`** (JWT; admin role; `X-Requested-With` is required on `POST` / `PUT` / `PATCH` / `DELETE`, not on `GET`). Routes that change the host — including netplan/firewall **commit** — return **403** `{"error":"step_up_required"}` until the session confirms its password with `POST /api/v1/auth/confirm`, which holds for 5 minutes; reads and the diagnostics do not need it ([API.md](API.md)). Privileged work is delegated to **`easy-waf-hostd`** (root broker on **`/run/easy-waf/hostd.sock`**, `root:easy-waf` **0660**). **`easy-waf-api`** stays unprivileged (`NoNewPrivileges=true`, `ProtectSystem=strict`) and sends typed JSON requests over the socket; the broker re-validates every operation (same allowlists as the API) and runs **`exec.Command`** without a shell.

| Area | Methods | Notes |
|------|---------|--------|
| Network | `GET /host/network`; `PUT /host/network/netplan` returns **410 Gone** | `ip -j` snapshot; netplan file `/etc/netplan/99-easy-waf.yaml` |
| Network (safe apply) | `POST /host/network/netplan/apply`, `POST /host/network/netplan/commit` | Body `{ "yaml", "rollback_seconds" }` (default/clamp 30–600s, default 90). Broker backs up YAML, applies, schedules **`systemd-run`** → **`easy-waf-hostd revert netplan <token>`** if not committed. Audit stores `token_sha256`, not the raw token. |
| Firewall | `GET /host/firewall`; `PUT /host/firewall/ruleset` and `POST /host/firewall/apply` return **410 Gone** | Managed file `/etc/nftables/easy-waf.nft`. A ruleset that uses `include` is refused (the broker runs `nft -c -f` as root and echoes nft's errors, so an include could read root-only files back). After every load the broker reloads the root-owned `/etc/nftables/easy-waf-guard.nft`, so no ruleset can open the management ports beyond the configured networks; see [SECURITY.md](SECURITY.md). |
| Firewall (safe apply) | `POST /host/firewall/apply-rollback`, `POST /host/firewall/commit` | Same rollback window via broker `nft-apply-confirm` / `nft-commit`. API runs `nft -c` **before** the broker (invalid ruleset → 4xx, no timer). Audit stores `token_sha256`. |
| Services | `GET /host/services`, `POST /host/services/{unit}/{action}` | Whitelisted systemd units only. `stop` and `disable` of `nftables.service` are refused by the API and the broker. |
| Journal | `GET /host/journal?unit=&lines=&since=&until=&priority=` | `journalctl` via broker; **`unit` required** (allowlisted); `-n` capped; no `verbose`/`export` |
| Updates | `GET /host/updates`, `POST /host/updates/update`, `POST /host/updates/upgrade` (legacy), `POST /host/updates/upgrade/stream` (NDJSON live log), `POST /host/updates/attach/stream?run_id=…` (read-only observation), `GET /host/updates/upgrade/status`, `GET /host/updates/upgrade/log`, `GET /host/updates/autoremove/preview`, `POST /host/updates/autoremove/stream`, `POST /host/updates/clean` | broker proxies to the independent root APT service |
| Disk | `GET /host/disk` | `statfs` in API process (no root); optional `cache_bytes`, `removable_count` via broker |
| Power | `POST /host/power/reboot`, `POST /host/power/shutdown` | |
| Users | `GET /host/users`, `POST /host/users`, `DELETE /host/users/{name}`, `PUT /host/users/{name}/ssh-keys` | Lists local accounts with **uid ≥ 1000, plus `root`**. `root` and `easy-waf` are **protected**: create, delete and ssh-key writes on those names are refused with 400 — `user protected`, `user cannot be deleted` and `user is protected or invalid` respectively — in the API *and* again in the broker. The broker also refuses ssh-key writes and deletion for any root-equivalent account (members of `sudo`, `docker`, `lxd`, `easy-waf`, `haproxy`, …, or named by a sudoers rule) — see [SECURITY.md](SECURITY.md#host-management-apiv1host). |
| Diagnostics | `POST /host/diagnostics/ping`, `POST /host/diagnostics/trace` | JSON body `{ "host": "…" }`; `ping` also accepts `count` |

WAF tabs (Applications, HAProxy apply, etc.) remain on existing `/api/v1/*` routes; authentication, error handling and every other endpoint are in the [REST API reference](API.md).

Netplan, firewall and SSH-key writes use unique temporary inputs under `/var/lib/easy-waf/staging/`, mode 0600. Each input is closed before the broker reads it and removed after the synchronous operation returns, including validation and broker failures. Concurrent requests do not share filenames. Cleanup errors are reported together with any operation error; netplan staging files may contain Wi-Fi credentials and must not accumulate as history.

Each broker and APT-worker listener admits at most 32 concurrent handlers,
including connections still sending a request and long-running observers.
Excess connections close before decoding or execution; retry after capacity
becomes available. A privileged JSON request object, including leading whitespace,
is limited to 64 KiB. Oversized input is rejected without execution; closing a
socket with unread excess bytes can reset it before the error reply is received.
Large configuration files continue to use staged paths rather than inline JSON.
These transport limits do not bound all external-command or API process memory.

Ordinary command capture in both the root broker and local API runner retains
at most **4 MiB combined stdout/stderr per command**. The two pipe readers share
that budget. After it fills, excess output is consumed and discarded so a command
can finish without blocking on a full pipe. The reply reports incomplete capture,
even if the child exits zero; root replies keep a nonzero child exit code and
otherwise use code 1, with the actual zero exit stated in the error. Cancellation
and cleanup errors remain visible. Retained prefixes can end mid-line and are
not successful complete results. Narrow large journal queries with line/time
filters; very large ruleset/diagnostic output can also exceed this limit.
This policy includes APT simulations, not tracked APT mutations: mutations retain
their separate 1 MiB synchronous excerpt, live-delivery and 64 MiB saved-log
limits described below. It does not cap the subprocess's own memory or the API's
decoded responses.

Synchronous broker commands have a **two-minute execution budget per command**;
`apt-get` has **30 minutes** so a slow package transaction is not interrupted by
the ordinary control-command limit. APT belongs to `easy-waf-apt.service`, outside
the broker cgroup. It retains its run ID/log/result across broker stop or crash;
only root peers can reach its private socket and it accepts only APT opcodes.
The API's socket/request deadline is separate and can end its wait while
the worker is still finishing work. Earlier caller deadlines still apply to
ordinary broker control commands. These are not whole-operation budgets:
multi-command apply/recovery and filesystem/lock waits can take longer.

Local read-only API commands (network/service snapshots, update listings,
diagnostics and `nft -c`) use the same process policy as ordinary broker commands.
After parent exit/cancellation, inherited stdout/stderr waits last at most two
additional seconds; incomplete capture reports an error. On Linux/macOS these
commands get their own process group, canceled as a group and cleaned on return,
including successful parents that leave helpers behind. Caller cancellation and
the earlier of caller/command deadlines retain their error cause alongside output
or cleanup failures. Windows development uses native parent cancellation and
bounded pipe waits; it does not promise descendant termination. A descendant that
deliberately leaves its Unix group is outside this policy too. This is process
cleanup, not a service cgroup boundary; APT ownership remains in its separate
service, with successful package-started services allowed to continue.

After process exit or cancellation, captured stdout/stderr pipe waits are limited
to another two seconds. An inherited pipe that never closes is an output-capture
failure rather than a successful result. Linux/macOS commands run in their own
process group; cancellation terminates that group, and ordinary control commands
clean up remaining helpers before returning. Successful APT scripts retain their
normal service-start behavior; systemd-managed jobs are separate from the CLI
process group. Windows development uses native parent cancellation and bounded
pipe waits. Host broker peer verification is supported only on Linux; other
platforms reject connections except for the explicit unit-test bypass. The
`easy-waf` UID lookup is performed only on Linux.

Streaming APT has an independent 30-minute command context that survives client
disconnects. It reads output while reaping the parent concurrently, then allows
two seconds for the remaining stdout/stderr to drain. An inherited pipe that
stays open is closed and reported as incomplete capture, so it cannot leave the
completed transaction permanently active. Cancellation/deadline errors retain
their cause; Linux/macOS terminate the command group on cancellation or failure.
Successful scripts may leave services running once they release output pipes.
Command output and heartbeat callbacks are serialized. The executor stops and
joins its heartbeat before returning, so no heartbeat writes can follow the
final exit event or access the action log after the caller closes it. Queued
heartbeats are discarded after cancellation or completion.
These limits cover commands and pipe waits, not blocking filesystem I/O or a
blocked output callback.

Network and firewall commit stop both the rollback timer and its service before
deleting the pending backup. If cancellation or backup deletion fails, the broker
attempts an immediate rollback: systemd may have stopped the safety timer even
when its stop command reports failure. The confirmation still returns an error;
do not treat the change as kept. If recovery also fails, both errors are reported
and available recovery state is retained for retry. Canceling the confirmation
context does not suppress recovery. If apply fails, the broker also attempts an
immediate rollback even when systemd cancellation fails.

A repeated commit succeeds only when the root-owned receipt for that subsystem
matches the token. An absent backup alone does not prove confirmation: the change
may have reverted, or the token may be unknown. Such requests return an error
instead of `committed`. The receipt survives broker restart and contains only the
last confirmed token, with at most one file per subsystem. Starting another safe
apply invalidates its subsystem's old receipt. A new apply cannot reuse the token
in its current receipt. Pending changes from an older version remain
confirmable; an old completed change without a receipt is treated as unknown.
When recovery finds both a pending backup and a stale receipt, it invalidates the
receipt before restoring the backup. An invalidation failure leaves pending
recovery state available and is reported as an error.

The receipt is written after backup removal. If that later write fails, the error
explicitly says `change kept but recording confirmation failed`; check the current
configuration before retrying. A retry without a matching receipt does not invent
confirmation or change the live configuration.

The rollback timer is armed **before** changing the live configuration. The API's
`expires_at` comes from a conservative deadline recorded by hostd immediately
before arming it; time spent applying the change consumes that window. An older
broker that omits the optional `rollback_expires_at` response field uses a
fallback recorded before the API's broker call. The UI does not start a new
countdown or offer confirmation when the response already reports an expired
window. This deadline does not claim to predict systemd scheduling latency;
check the current configuration after expiry.

Only one unconfirmed change per subsystem (network or firewall) is allowed. Another apply, including the legacy immediate broker operations, is rejected until the pending change is committed or reverted. Apply, commit and revert serialize access to the live configuration; an interactive request during another mutation returns a busy error and can be retried. On Linux the broker and standalone timer process share a kernel lock on the root-owned state directory. The timer waits for an in-progress mutation before restoring the backup.

Before arming the timer, the existing configuration must pass the same policy validation used by rollback. An incompatible baseline (for example, an nftables `include` or unsupported netplan tunnel) rejects the new safe apply without changing the live file. Backups are limited to 16 MiB; oversized files are rejected rather than truncated. The generated no-managed-ruleset marker is restored by removing the newly declared tables, including on repeated apply/revert cycles.

A revert reports failure if the live netplan file cannot be removed or the pending backup cannot be deleted. Pending recovery state remains available for retry after the filesystem problem is repaired. Retrying an nftables revert that already wrote the no-managed-ruleset marker resumes guard reload and cleanup without attempting to rediscover removed tables. Timer-creation errors also report any failure to clean up their unused backup.

Before restoring live state, the broker atomically claims the root-owned backup
by renaming `KIND-TOKEN.bak` to `KIND-TOKEN.reverting` in
`/var/lib/easy-waf-hostd/rollback`. Once claimed, it cannot be committed, and new
changes for that subsystem are refused until recovery finishes. Command, guard
reload and cleanup failures retain the claimed backup for retry; startup recovery
discovers both file states. After fixing the underlying error, an operator can
retry with `sudo easy-waf-hostd revert KIND TOKEN` (`KIND` is `nft` or `netplan`).
Conflicting pending/reverting files are preserved and require inspection rather
than choosing or overwriting one. Do not downgrade to an older broker while a
`.reverting` file remains; finish recovery with the current version first.

For a nonempty nftables baseline, rollback recreates the tables declared in the current and saved managed files, then loads the saved rules in the same nft transaction. Simply loading the saved file would merge rules and retain changes. Tables belonging to other owners are left alone. Table removal uses an atomic ensure-exists/delete pair and does not require kernel support for `destroy table`. The nightly `nft-rollback` E2E job verifies this with real nftables on Ubuntu 24.04 inside a private network namespace; its integration test requires both the `integration` build tag and explicit `RUN_NFT_ROLLBACK_INTEGRATION=1` opt-in.

### `POST /host/updates/upgrade/stream` (live apt log)

- **Content-Type:** `application/x-ndjson` — one JSON object per line; API flushes with `http.ResponseController.Flush()` after each line (chunked streaming).
- **Events:** `{"type":"line","data":"…"}` and `{"type":"exit","code":N,"error":"…"}`.
- **Completion:** the broker must send a newline-terminated `exit` event with an explicit integer `code` (including zero). EOF without it, malformed/unknown events, contradictory zero-code errors, and records over 8 MiB are transport/protocol failures, not successful apt completion. The API reports these as `exit` code `-1` and does not record a successful completion audit. A valid terminal event completes the stream without waiting for socket EOF.
- **Browser consumption:** the panel also requires newline-terminated, well-typed `line`/`exit` objects and a safe integer exit code, rejects malformed UTF-8 and code-zero errors, and bounds a pending record at 8 MiB of original UTF-8 bytes (excluding LF), including across read chunks. Missing/truncated terminal data shows an interrupted-observation warning, never success. The first valid exit completes observation without waiting for HTTP EOF; reader cancellation/release runs on every success/failure path and does not stop host package execution. Nonzero/unknown reconnect results remain visible even without an error string. Appended live text retains at most 2 Mi UTF-16 code units, including a visible older-output-omitted notice; newest output and intact surrogate pairs are retained. This limits pending parsing and appended live display, not total browser/DOM/network memory or explicit saved-log download allocation; server saved-log retention and incomplete-log reporting remain separate.
- **Broker:** `apt-upgrade-stream` runs `apt-get -y -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=120 upgrade` (`DEBIAN_FRONTEND=noninteractive`). Emits a start line immediately, then heartbeat lines if apt is silent for ~15s, then apt stdout/stderr.
- **Single process:** only one broker-owned APT mutation (`update`, `upgrade`, `autoremove` or `clean`) runs at a time. A second stream request during an active stream **attaches** as a follower (tails root-only `/var/lib/easy-waf-hostd/apt-action.log` through the broker), and does not start another apt. First line: `==> attaching to apt action already in progress ...`.
- **All broker mutations share ownership:** synchronous `apt-update`, `apt-upgrade` and `apt-clean` use the same reservation, tracked PID executor, saved log and completion policy as streaming upgrade/autoremove. Busy synchronous requests fail without invoking APT or changing the owner/log/result. Streams requested during a known synchronous operation also fail busy rather than silently claiming that operation's result. Existing stream-to-stream attach behavior remains; simulations and cache-size reads stay available. This coordinates broker-owned work; APT/dpkg's own locks still arbitrate package managers outside the broker.
- **Synchronous compatibility:** the existing JSON opcodes/routes remain. Mutations run noninteractively with a 30-minute command budget (earlier caller deadlines apply), bounded pipe waits and process recovery metadata. Their `stdout` is a merged complete-line excerpt of progress/stdout/stderr up to 1 MiB, with an explicit truncation notice; the saved log retains its separate 64 MiB limit. Failed replies retain the actual nonzero command code, context cause and a bounded diagnostic tail. A client/socket timeout can end its wait before the broker finishes; inspect common action status/log before retrying.
- **Operation-aware status:** `/host/updates/upgrade/status` remains the common/legacy status alias. Known local runs additionally include `action` (`update`, `upgrade`, `clean` or `autoremove`) and `stream` (boolean). Every retained local/recovered record includes a random 32-character lowercase hexadecimal `run_id`, unchanged when that run finishes. The panel uses it to observe synchronous or streaming work, displays verification errors directly and uses generic package-operation completion messages. Older brokers without a valid `run_id` show saved-log guidance; automatic reconnect never falls back to a mutation stream.
- **Follower consistency:** each follower retains the original run's result and log descriptor. Starting the next action replaces the saved log without truncating an older follower's file. Replay uses bounded batches and complete-line offsets, waits for incomplete appended lines, and drains the finished run before its final `exit`. Slow followers cannot switch to the next action's output or exit code; their old descriptors close when the last owner releases them.
- **Saved-log failures:** each action saves at most 64 MiB at complete-line boundaries. Create/write/sync/close failures or reaching that limit do not interrupt the package command or stop live delivery. The final stream/status reports incomplete logging, includes the actual command exit code in its error, and returns a nonzero result (retaining an already nonzero command code). Inspect package state before retrying: an incomplete saved log does not mean packages were rolled back. A follower that cannot read its saved log reports an explicit error; it does not claim success or cancel the action.
- **Slow clients:** primary live output uses an owned delivery worker with a queue capped at 1024 lines and 4 MiB of unescaped pending text, plus one in-flight line and bounded JSON framing. Package callbacks save the log and offer output without waiting for that client's socket. Queue overflow reports `exit` code `-1` with saved-log/status guidance when the connection remains writable, then closes the connection; a write timeout/disconnect ends delivery without claiming successful completion. Neither failure changes the command's actual result in status or truncates its saved log. Healthy queues drain before the original terminal result. Logging remains synchronous disk work; a log error does not disable otherwise healthy live delivery.
- **Socket lifetime:** each broker NDJSON write is limited to five seconds and cannot extend the 35-minute overall stream lifetime. The delivery worker is joined before its handler returns; failed connections close while the package command continues. Followers stop and release their record on write failure. Idle followers send an observation-only heartbeat about every 15 seconds (including recovered runs with no new log output), allowing failed/expired sockets to be detected; these observer heartbeats do not alter the saved package log.
- **HTTP delivery:** each API event write and flush shares a five-second deadline, cleared after successful flush so idle waits remain valid, including on HTTP/2. Write/flush failures end the relay without another write attempt or a completion audit. Closing the broker connection only stops that subscriber; APT and its saved log continue independently.
- **Ownership:** an action stays active in `easy-waf-apt.service` from reservation until its worker collects the result, including before PID publication. Broker stop/crash does not replace its run ID/log/result. If the APT service itself restarts, surviving saved process identity is observed separately; when it disappears without a collected result, its exit status is unknown (`exit_code: -1`), not invented as success. Inspect the saved log when a prior run is unavailable.
- **Recovered process identity (Linux):** new PID records retain the leading numeric PID for older brokers, followed by a `v1` record containing the Linux boot UUID and process start ticks. Recovery compares that identity, excludes zombie/dead states, and pins the original process independently of later PID-file removal/replacement. A different boot or reused PID cannot impersonate a versioned record's saved action. Legacy numeric-only files are accepted only when the live executable is `apt-get` (including a replaced/deleted binary), then pinned to its observed epoch; this conservative fallback cannot prove a legacy file's historical process identity. See [proc stat fields](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html), [kernel boot_id](https://docs.kernel.org/admin-guide/sysctl/kernel.html#random) and [opened proc descriptors](https://docs.kernel.org/filesystems/proc.html).
- **Unverifiable recovery:** metadata or process-inspection errors retain the stream reservation and report `active: true`, `exit_code: -1` with a verification error. Here `active` means the reservation cannot safely be released; it does not assert the process is running. A second stream reports the error instead of starting another action. Inspection is retried on subsequent polls and can recover when access is restored. Stale/unrelated/dead processes report an inactive, unknown outcome. Windows/macOS development builds do not emulate Linux process recovery; packaged broker execution remains Linux-only.
- **`code: -1`** reports observation, log-read or live-delivery failures (with explicit `error`), not “already running”. A live-delivery failure does not replace the actual command result retained in action status.
- **Client disconnect** does not stop apt; the independent worker finishes the transaction. Worker TERM closes observers and drains active synchronous/streaming package work, with a 32 minute service stop allowance. Forcing that owner with SIGKILL or losing power can still interrupt APT.
- **Easy WAF self-upgrade:** package configuration queues `easy-waf-hostd-restart.service`. The separate helper reserves the private execution lease, then both real package locks, and holds them across active-only worker/broker restart. API/acmed jobs are queued without waiting, so the ACME drain cannot consume the caller's APT budget. Needrestart leaves the four managed processes to the package. API restart can end the panel connection; reopen System for the worker's saved log/status. A worker restart can lose its last in-memory result. See [deployment checks](DEPLOYMENT.md).
- **Output capture:** primary and attach readers accept lines up to 1 MiB. If stdout/stderr scanning fails (including an oversized line), the broker drains the remaining pipe with bounded memory so apt can finish, then reports incomplete output capture. A nonzero apt exit code is preserved; a zero exit is not presented as success when capture failed.
- **Request cancellation and deadlines** close the API's broker connection and unblock socket reads/writes. Regular broker calls are bounded by two minutes or an earlier caller deadline; streams use a 15-second connection timeout and retain the caller's context for subsequent I/O. Canceling a stream stops observation while the APT service continues independently. Broker forwarding also bounds each client write to five seconds.
- **`GET /host/updates/upgrade/status`** — `{"active":true|false,"exit_code":…,"error":…,"run_id":"…"}` for UI observation on the System tab. `run_id` is omitted when no record is retained. The API requires an explicit lowercase `active` boolean in a status object of at most 64 KiB; present known metadata must have the correct non-null type. Missing optional fields from older brokers remain omitted, while unknown future fields and their exact JSON numbers are retained. Duplicate top-level names, malformed/ambiguous/trailing data and invalid known fields return generic HTTP 502; broker transport/command failure stays HTTP 500. Neither becomes an invented `active:false` or exit code. This validates the payload after the ordinary broker RPC, not a new generic transport-memory limit. Replies and UI fetches use `no-store`.
- **Status uncertainty in the panel:** HTTP/JSON/network/schema failure displays a verification warning with refresh/saved-log guidance. It never starts an action or falls back to a mutation stream. Fresh failed/unknown completed outcomes are visible, and a verified healthy idle status clears only status-owned notices. A newer poll or package interaction invalidates older pending polls, even when message text is unchanged; late replies cannot replace a newer action's result. Correct older active replies without a valid `run_id` retain saved-log guidance instead of automatic reconnect.
- **One panel interaction at a time:** a live stream/reconnect, update check or cache cleanup owns the panel's package controls until its response/reader and error handling finish. Reopening System while owned does not poll or attach again, and competing callbacks cannot send another mutation. Disk replies cannot enable cache cleanup during ownership; releasing controls retains the known small-cache condition. Late automatic package-list replies cannot overwrite a newer interaction's output. This is per-page UI coordination; server-side APT admission still arbitrates other pages/clients, and disconnecting observation does not cancel host package execution.
- **`GET /host/updates/upgrade/log`** — last saved log snapshot, as plain text. The API uses the read-only `apt-action-log-stream` opcode, receiving 32 KiB source chunks and an explicit download result. The worker pins the original descriptor and observed size (at most 64 MiB); later appends/replacement cannot extend it or change the selected file. Unicode text matches the legacy JSON download. A successful download means the snapshot was read, not that APT succeeded or finished. No APT action or observation record is created.
- **Download resources and errors:** the API admits two saved-log downloads per process; excess requests get HTTP 503 with `Retry-After: 1`. It validates the complete worker result in a private temporary file before committing HTTP 200, so partial/read-failed data remains HTTP 500. Each file is bounded to 192 MiB of decoded text (64 MiB source can expand threefold when invalid UTF-8 bytes become U+FFFD); two admitted files use at most 384 MiB of temporary storage, ordinarily at most 128 MiB for valid UTF-8 logs. The configured OS temp directory must be writable with sufficient space. Files close/delete on every normal, error or canceled path. Unix uses mode 0600 and unlinks the name immediately; Windows inherits the configured temp-directory ACLs and removes the name after close. A crashed Windows development process can leave a temporary file requiring cleanup. Storage may be disk or tmpfs according to host configuration; this is not a universal RSS limit.
- **Download delivery:** the existing URL returns validated text with `Content-Length` and `Cache-Control: no-store`, using 32 KiB HTTP writes. Fetch plus delivery has a two-minute overall budget (or earlier caller deadline); each write/flush has at most five seconds, restoring the overall deadline between chunks. A failed HTTP write is not retried or followed by an appended error; the declared length lets clients detect truncation. Worker/sink failure closes the read-only broker connection immediately and never cancels package work. Legacy `apt-upgrade-log` / `apt-action-log` JSON aliases remain for older clients. An API paired with an older broker/worker fails explicitly until the normal deferred service refresh finishes; it never falls back to whole-log JSON allocation or an APT mutation.
- **UI:** `fetch` POST + `ReadableStream` (not `EventSource`).

Legacy `POST /host/updates/upgrade` still blocks until the non-streaming `apt-upgrade` opcode completes.

### `POST /host/updates/attach/stream?run_id=…` (read-only observation)

- Requires an admin session and `X-Requested-With`, like saved-log access plus the usual POST CSRF check. It stays outside mutation step-up because it only reads an existing run. Explicit start/update/upgrade/cleanup routes retain step-up protection.
- Requires exactly one `run_id` query value with 32 lowercase hexadecimal characters. The API forwards only `apt-action-attach-stream <run_id>`; malformed/missing/duplicate IDs fail with HTTP 400 before broker access. IDs select records; they do not grant authorization.
- The broker atomically matches and retains that existing record. If the run finished after the status poll, the observer drains its saved output and original result. A missing/replaced record or an ID from before broker restart returns NDJSON `exit` code `-1` with an explicit error. This opcode cannot reserve/start APT, replace the log or clear PID bookkeeping. Unsupported brokers fail explicitly; there is no mutating fallback.
- Already attached readers retain the selected descriptor/result even when a later operation starts. Reconstructed surviving processes receive new observation IDs after broker restart; their eventual exit result remains unknown, as described above.
- Uses the same NDJSON framing/flush/completion rules as mutation streams. Audit events are `host_apt_attach` and `host_apt_attach_done`, including `run_id`; observation does not emit upgrade-start/completion audit events. Transport/protocol failure does not emit a completion audit event.

### `GET /host/updates/autoremove/preview`

- **Safe:** runs `apt-get -s autoremove` via broker opcode `apt-autoremove-simulate` (no packages removed).
- **Response:** `{ "output": "…", "packages": ["pkg", …] }` — `packages` parsed from `Remv` lines when present.

### `POST /host/updates/autoremove/stream` (live cleanup log)

- Same NDJSON contract as upgrade stream (`line` / `exit`, flush, heartbeat, attach).
- **Broker:** `apt-autoremove-stream` runs `apt-get -y -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=120 autoremove` (no `--purge`).
- Shares the same single-flight lock as `apt-upgrade-stream`.

### `GET /host/disk`

- **Mounts:** `statfs` on `/` and `/var` (deduplicated by filesystem ID). Each entry: `path`, `total_bytes`, `free_bytes` (available to unprivileged user via `Bavail`), `used_bytes`, `used_percent`.
- **`cache_bytes`:** size of `/var/cache/apt/archives` via broker `apt-cache-size` (`du -sb`), when available.
- **`removable_count`:** count of packages from `apt-autoremove-simulate` preview, when available.

### `POST /host/updates/clean`

- Runs `apt-get clean` via broker opcode `apt-clean` (`-o DPkg::Lock::Timeout=120`). Removes downloaded `.deb` archives only (installed packages unchanged).
- **Response:** `{ "freed_bytes": N }` — difference in `cache_bytes` before and after.
- **Audit:** `host_apt_clean`. No confirmation required (safe operation).
