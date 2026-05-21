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
| Updates | `GET /host/updates`, `POST /host/updates/update`, `POST /host/updates/upgrade` | apt |
| Power | `POST /host/power/reboot`, `POST /host/power/shutdown` | |
| Users | `GET /host/users`, `POST /host/users`, `DELETE /host/users/{name}`, `PUT /host/users/{name}/ssh-keys` | Local accounts uid ≥ 1000 |
| Diagnostics | `POST /host/diagnostics/ping`, `POST /host/diagnostics/trace` | JSON body `{ "host": "…" }` |

WAF tabs (Applications, HAProxy apply, etc.) remain on existing `/api/v1/*` routes.
