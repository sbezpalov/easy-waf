# Host management API (Ubuntu)

Authenticated routes under **`/api/v1/host/*`** (JWT + `X-Requested-With`). Privileged work is delegated to **`easy-waf-hostd`** (root broker on **`/run/easy-waf/hostd.sock`**, `root:easy-waf` **0660**). **`easy-waf-api`** stays unprivileged (`NoNewPrivileges=true`, `ProtectSystem=strict`) and sends typed JSON requests over the socket; the broker re-validates every operation (same allowlists as the API) and runs **`exec.Command`** without a shell.

| Area | Methods | Notes |
|------|---------|--------|
| Network | `GET /host/network`, `PUT /host/network/netplan` (legacy immediate apply) | `ip -j` snapshot; netplan file `/etc/netplan/99-easy-waf.yaml` |
| Network (safe apply) | `POST /host/network/netplan/apply`, `POST /host/network/netplan/commit` | Body `{ "yaml", "rollback_seconds" }` (default/clamp 30–600s, default 90). Broker backs up YAML, applies, schedules **`systemd-run`** → **`easy-waf-hostd revert netplan <token>`** if not committed. |
| Firewall | `GET /host/firewall`, `PUT /host/firewall/ruleset`, `POST /host/firewall/apply` (legacy) | Managed file `/etc/nftables/easy-waf.nft` |
| Firewall (safe apply) | `POST /host/firewall/apply-rollback`, `POST /host/firewall/commit` | Same rollback window via broker `nft-apply-confirm` / `nft-commit`. API runs `nft -c` **before** the broker (invalid ruleset → 4xx, no timer). |
| Services | `GET /host/services`, `POST /host/services/{unit}/{action}` | Whitelisted systemd units only |
| Journal | `GET /host/journal?unit=&lines=&since=` | `journalctl` via broker |
| Updates | `GET /host/updates`, `POST /host/updates/update`, `POST /host/updates/upgrade` (legacy), `POST /host/updates/upgrade/stream` (NDJSON live log), `GET /host/updates/upgrade/status`, `GET /host/updates/upgrade/log` | apt via broker |
| Power | `POST /host/power/reboot`, `POST /host/power/shutdown` | |
| Users | `GET /host/users`, `POST /host/users`, `DELETE /host/users/{name}`, `PUT /host/users/{name}/ssh-keys` | Local accounts uid ≥ 1000 |
| Diagnostics | `POST /host/diagnostics/ping`, `POST /host/diagnostics/trace` | JSON body `{ "host": "…" }` |

WAF tabs (Applications, HAProxy apply, etc.) remain on existing `/api/v1/*` routes.

### `POST /host/updates/upgrade/stream` (live apt log)

- **Content-Type:** `application/x-ndjson` — one JSON object per line; API flushes with `http.ResponseController.Flush()` after each line (chunked streaming).
- **Events:** `{"type":"line","data":"…"}` and `{"type":"exit","code":N,"error":"…"}`.
- **Broker:** `apt-upgrade-stream` runs `apt-get -y -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=120 upgrade` (`DEBIAN_FRONTEND=noninteractive`). Emits a start line immediately, then heartbeat lines if apt is silent for ~15s, then apt stdout/stderr.
- **Single process:** only one `apt` runs. A second `POST …/upgrade/stream` while active **attaches** as a follower (tails `/var/lib/easy-waf/apt-upgrade.log`), does not start another apt. First line: `==> attaching to upgrade already in progress ...`.
- **`code: -1`** is reserved for attach/log read failures (with explicit `error`), not for “already running”.
- **Client disconnect** does not stop apt; the broker finishes the transaction.
- **`GET /host/updates/upgrade/status`** — `{"active":true|false,"exit_code":…,"error":…}` for UI re-attach on the System tab.
- **`GET /host/updates/upgrade/log`** — last saved log file (read-only).
- **UI:** `fetch` POST + `ReadableStream` (not `EventSource`).

Legacy `POST /host/updates/upgrade` still blocks until the non-streaming `apt-upgrade` opcode completes.
