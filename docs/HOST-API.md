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
| Updates | `GET /host/updates`, `POST /host/updates/update`, `POST /host/updates/upgrade` (legacy), `POST /host/updates/upgrade/stream` (NDJSON live log), `GET /host/updates/upgrade/status`, `GET /host/updates/upgrade/log`, `GET /host/updates/autoremove/preview`, `POST /host/updates/autoremove/stream`, `POST /host/updates/clean` | apt via broker |
| Disk | `GET /host/disk` | `statfs` in API process (no root); optional `cache_bytes`, `removable_count` via broker |
| Power | `POST /host/power/reboot`, `POST /host/power/shutdown` | |
| Users | `GET /host/users`, `POST /host/users`, `DELETE /host/users/{name}`, `PUT /host/users/{name}/ssh-keys` | Lists local accounts with **uid ≥ 1000, plus `root`**. `root` and `easy-waf` are **protected**: create, delete and ssh-key writes on those names are refused with 400 — `user protected`, `user cannot be deleted` and `user is protected or invalid` respectively — in the API *and* again in the broker. The broker also refuses ssh-key writes and deletion for any root-equivalent account (members of `sudo`, `docker`, `lxd`, `easy-waf`, `haproxy`, …, or named by a sudoers rule) — see [SECURITY.md](SECURITY.md#host-management-apiv1host). |
| Diagnostics | `POST /host/diagnostics/ping`, `POST /host/diagnostics/trace` | JSON body `{ "host": "…" }`; `ping` also accepts `count` |

WAF tabs (Applications, HAProxy apply, etc.) remain on existing `/api/v1/*` routes; authentication, error handling and every other endpoint are in the [REST API reference](API.md).

Netplan, firewall and SSH-key writes use unique temporary inputs under `/var/lib/easy-waf/staging/`, mode 0600. Each input is closed before the broker reads it and removed after the synchronous operation returns, including validation and broker failures. Concurrent requests do not share filenames. Cleanup errors are reported together with any operation error; netplan staging files may contain Wi-Fi credentials and must not accumulate as history.

Network and firewall commit stop both the rollback timer and its service before deleting the pending backup. If cancellation or backup deletion fails, the broker returns an error and keeps the pending state for recovery; do not treat the change as confirmed. A repeated commit after the backup has already been removed is safe. If apply fails, the broker still attempts an immediate rollback even when systemd cancellation fails.

Only one unconfirmed change per subsystem (network or firewall) is allowed. Another apply, including the legacy immediate broker operations, is rejected until the pending change is committed or reverted. Apply, commit and revert serialize access to the live configuration; an interactive request during another mutation returns a busy error and can be retried. On Linux the broker and standalone timer process share a kernel lock on the root-owned state directory. The timer waits for an in-progress mutation before restoring the backup.

Before arming the timer, the existing configuration must pass the same policy validation used by rollback. An incompatible baseline (for example, an nftables `include` or unsupported netplan tunnel) rejects the new safe apply without changing the live file. Backups are limited to 16 MiB; oversized files are rejected rather than truncated. The generated no-managed-ruleset marker is restored by removing the newly declared tables, including on repeated apply/revert cycles.

A revert reports failure if the live netplan file cannot be removed or the pending backup cannot be deleted. Pending recovery state remains available for retry after the filesystem problem is repaired. Retrying an nftables revert that already wrote the no-managed-ruleset marker resumes guard reload and cleanup without attempting to rediscover removed tables. Timer-creation errors also report any failure to clean up their unused backup.

For a nonempty nftables baseline, rollback recreates the tables declared in the current and saved managed files, then loads the saved rules in the same nft transaction. Simply loading the saved file would merge rules and retain changes. Tables belonging to other owners are left alone. Table removal uses an atomic ensure-exists/delete pair and does not require kernel support for `destroy table`. The nightly `nft-rollback` E2E job verifies this with real nftables on Ubuntu 24.04 inside a private network namespace; its integration test requires both the `integration` build tag and explicit `RUN_NFT_ROLLBACK_INTEGRATION=1` opt-in.

### `POST /host/updates/upgrade/stream` (live apt log)

- **Content-Type:** `application/x-ndjson` — one JSON object per line; API flushes with `http.ResponseController.Flush()` after each line (chunked streaming).
- **Events:** `{"type":"line","data":"…"}` and `{"type":"exit","code":N,"error":"…"}`.
- **Broker:** `apt-upgrade-stream` runs `apt-get -y -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=120 upgrade` (`DEBIAN_FRONTEND=noninteractive`). Emits a start line immediately, then heartbeat lines if apt is silent for ~15s, then apt stdout/stderr.
- **Single process:** only one `apt` action (`upgrade` or `autoremove`) runs at a time. A second stream request while active **attaches** as a follower (tails root-only `/var/lib/easy-waf-hostd/apt-action.log` through the broker), and does not start another apt. First line: `==> attaching to apt action already in progress ...`.
- **`code: -1`** is reserved for attach/log read failures (with explicit `error`), not for “already running”.
- **Client disconnect** does not stop apt; the broker finishes the transaction.
- **`GET /host/updates/upgrade/status`** — `{"active":true|false,"exit_code":…,"error":…}` for UI re-attach on the System tab.
- **`GET /host/updates/upgrade/log`** — last saved log file (read-only).
- **UI:** `fetch` POST + `ReadableStream` (not `EventSource`).

Legacy `POST /host/updates/upgrade` still blocks until the non-streaming `apt-upgrade` opcode completes.

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
