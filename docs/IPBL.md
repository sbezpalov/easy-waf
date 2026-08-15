# IP blacklist (IPBL) and IP allowlist (IPWL)

## Model

### Blacklist

- **Local entries** (`ipbl_local`): administrator-defined IPv4/IPv6 or CIDR strings, editable via API (`/api/v1/ipbl/local`).
- **External sources** (`ipbl_external_sources`): HTTP(S) URLs pointing to plain-text lists (one IP or CIDR per line, `#` comments allowed). Fetched periodically when `SyncAndWrite` runs (on HAProxy apply and via `POST /api/v1/ipbl/sync`).

**SSRF protection (default):** only **public** feed URLs are allowed. **Hard-blocked** destinations (loopback, link-local, metadata **169.254.x**, CGNAT **100.64.0.0/10**, unspecified) are never allowed, even via allowlist.

**Trusted internal feeds (split-DNS):** set global **`ipbl_fetch_allowed_cidrs`** to the RFC1918 ranges where your feeds live (e.g. `192.168.1.0/24`). UI: **Security → IP Blacklist → Trusted internal CIDRs for feed fetch** (one CIDR per line). Checks run at URL save, sync, dial time, and on redirects.

Deprecated: **`ipbl_allow_private_fetch`** — when `true` and `ipbl_fetch_allowed_cidrs` is empty, allows all RFC1918 only (not loopback/metadata). Prefer explicit CIDRs. See [SECURITY.md](SECURITY.md) and [DNS.md](DNS.md).

### Allowlist (trusted sources)

- **Local entries** (`ipwl_local`): `id`, `cidr`, `comment`, `created_at`. Managed via API (`GET` / `POST` / `DELETE /api/v1/ipwl/local/…`).
- **Global flags** (in `global_settings_json`): `ip_allowlist_map_path` (default `state/haproxy/ip_allowlist.map`), `ipwl_enabled` (default `false`).

## HAProxy integration

### Blacklist

Merged deny addresses are written to `settings.ip_blacklist_map_path` (default under `/var/lib/easy-waf/haproxy/ip_blacklist.map`). When the file contains at least one non-comment line, the generated config adds:

```text
acl ipbl_black src -f /path/to/ip_blacklist.map
http-request deny deny_status 403 if ipbl_black
```

Disable external merging with global setting `ipbl_external_enabled: false` (SME “air-gapped” mode).

### Allowlist

When **`ipwl_enabled`** is `true` and the allowlist map file has at least one valid line, every enabled application frontend (and each app backend for rate limiting) includes rules so trusted sources are not blocked by the IP blacklist or per-app HTTP rate limits:

```text
acl ipwl_white src -f /path/to/ip_allowlist.map
http-request allow if ipwl_white
```

These lines are emitted **before** the blacklist `http-request deny` and before other frontend HTTP rules that could block traffic. On backends, the rate-limit deny is applied only when the client is **not** on the allowlist (`!ipwl_white`).

The allowlist map is regenerated on **HAProxy apply** (`RenderFromStore`) and when **`POST /api/v1/ipbl/sync`** runs (same pipeline refreshes both blacklist and allowlist files).

## Caching and performance

External blacklist lists are **not** resolved per request: they are fetched during sync, validated, merged into a single file, then referenced by HAProxy from disk. The allowlist is built only from the database (`ipwl_local`).
