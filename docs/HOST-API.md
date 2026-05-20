# Host management API (Ubuntu)

Authenticated routes under **`/api/v1/host/*`** (JWT + `X-Requested-With`). Requires install-time **`/usr/lib/easy-waf/host-privileged.sh`** and **`/etc/sudoers.d/easy-waf-host`**.

| Area | Methods | Notes |
|------|---------|--------|
| Network | `GET /host/network`, `PUT /host/network/netplan` | `ip -j` snapshot; netplan staged to `/etc/netplan/99-easy-waf.yaml` |
| Firewall | `GET /host/firewall`, `PUT /host/firewall/ruleset`, `POST /host/firewall/apply` | Managed file `/etc/nftables/easy-waf.nft` |
| Services | `GET /host/services`, `POST /host/services/{unit}/{action}` | Whitelisted systemd units only |
| Journal | `GET /host/journal?unit=&lines=&since=` | `journalctl` via helper |
| Updates | `GET /host/updates`, `POST /host/updates/update`, `POST /host/updates/upgrade` | apt |
| Power | `POST /host/power/reboot`, `POST /host/power/shutdown` | |
| Users | `GET /host/users`, `POST /host/users`, `DELETE /host/users/{name}`, `PUT /host/users/{name}/ssh-keys` | Local accounts uid ≥ 1000 |
| Diagnostics | `POST /host/diagnostics/ping`, `POST /host/diagnostics/trace` | JSON body `{ "host": "…" }` |

WAF tabs (Applications, HAProxy apply, etc.) remain on existing `/api/v1/*` routes.
