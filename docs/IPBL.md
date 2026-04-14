# IP blacklist (IPBL)

## Model

- **Local entries** (`ipbl_local`): administrator-defined IPv4/IPv6 or CIDR strings, editable via API (`/api/v1/ipbl/local`).
- **External sources** (`ipbl_external_sources`): HTTP(S) URLs pointing to plain-text lists (one IP or CIDR per line, `#` comments allowed). Fetched periodically when `SyncAndWrite` runs (on HAProxy apply and via `POST /api/v1/ipbl/sync`).

## HAProxy integration

Merged addresses are written to `settings.ip_blacklist_map_path` (default under `/var/lib/easy-waf/haproxy/ip_blacklist.map`). When the file contains at least one non-comment line, the generated config adds:

```text
acl ipbl_black src -f /path/to/ip_blacklist.map
http-request deny deny_status 403 if ipbl_black
```

Disable external merging with global setting `ipbl_external_enabled: false` (SME “air-gapped” mode).

## Caching and performance

External lists are **not** resolved per request: they are fetched during sync, validated, merged into a single file, then referenced by HAProxy from disk.
