# Security profiles (MVP)

| Profile | Rate (RPS / burst) | Server timeout | Path blocks | Notes |
|---------|-------------------|----------------|-------------|--------|
| `balanced` | 50 / 100 | 50s | default probes | General home apps |
| `strict` | 20 / 40 | 30s | extended | Hardened |
| `trusted-lan` | 200 / 400 | 120s | minimal | High trust / LAN-heavy |
| `public-app` | 30 / 60 | 60s | default | Internet-exposed generic |
| `home-assistant` | 40 / 80 | 3600s | default | Long-lived WS/SSE |

Implementation: profile metadata lives in `internal/profiles`. The HAProxy template (`internal/haproxy/render.go`) applies:

- **Per vhost (frontend):** `BlockPaths` and `ExtraBlockedMethods` from the selected profile, scoped with `hdr(host)`.
- **Per backend:** `ConnectTimeout`, `ServerTimeout`, `HTTPKeepAlive`, stick-table **`http_req_rate(10s)`** vs **`RateLimitBurst`**, plus existing WebSocket/health/`server` lines.

`GeoDefaultDeny` is reserved for a future GeoIP integration and is not emitted yet.
