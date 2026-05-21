# Host management API (Ubuntu)

Authenticated routes under **`/api/v1/host/*`** (JWT + `X-Requested-With`). Requires install-time **`/usr/lib/easy-waf/host-privileged.sh`** and **`/etc/sudoers.d/easy-waf-host`**.

| Area | Methods | Notes |
|------|---------|--------|
| Network | `GET /host/network`, `PUT /host/network/netplan` (legacy immediate apply) | `ip -j` snapshot; netplan file `/etc/netplan/99-easy-waf.yaml` |
| Network (safe apply) | `POST /host/network/netplan/apply`, `POST /host/network/netplan/commit` | Body `{ "yaml", "rollback_seconds" }` (default/clamp 30–600s, default 90). Returns `{ "token", "expires_at" }`. On apply, `host-privileged.sh netplan-apply-confirm` backs up current YAML, runs `netplan generate` + `netplan apply`, then schedules **`systemd-run --on-active=…`** → `netplan-revert <token>` if not committed. **Commit** stops the transient unit and deletes the backup. Revert runs **without** `easy-waf-api` (independent of API process). |
| Firewall | `GET /host/firewall`, `PUT /host/firewall/ruleset`, `POST /host/firewall/apply` (legacy) | Managed file `/etc/nftables/easy-waf.nft` |
| Firewall (safe apply) | `POST /host/firewall/apply-rollback`, `POST /host/firewall/commit` | Same rollback window as netplan via `nft-apply-confirm` / `nft-commit` / `nft-revert`. Go validates with `nft -c` **before** calling the helper (invalid ruleset → 4xx, no timer). |
| Services | `GET /host/services`, `POST /host/services/{unit}/{action}` | Whitelisted systemd units only |
| Journal | `GET /host/journal?unit=&lines=&since=` | `journalctl` via helper |
| Updates | `GET /host/updates`, `POST /host/updates/update`, `POST /host/updates/upgrade` | apt |
| Power | `POST /host/power/reboot`, `POST /host/power/shutdown` | |
| Users | `GET /host/users`, `POST /host/users`, `DELETE /host/users/{name}`, `PUT /host/users/{name}/ssh-keys` | Local accounts uid ≥ 1000 |
| Diagnostics | `POST /host/diagnostics/ping`, `POST /host/diagnostics/trace` | JSON body `{ "host": "…" }` |

WAF tabs (Applications, HAProxy apply, etc.) remain on existing `/api/v1/*` routes.
