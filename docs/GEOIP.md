# GeoIP: ipinfo vs MaxMind (MMDB)

Easy WAF resolves IP addresses to **ISO 3166-1 alpha-2** country codes for:

- **Batch enforcement** — HAProxy map generation on Apply / IPBL sync (when GeoIP is enabled).
- **Per-application GeoIP** — optional per-app policy and country lists.
- **Management UI** — lookup test on the Security tab.

Two backends are supported via global setting **`geoip_provider`**: **`ipinfo`** (default) and **`maxmind`**.

## ipinfo (HTTP API)

- Outbound HTTPS to `ipinfo.io` (rate-limited in-process; optional token **`GEOIP_IPINFO_TOKEN`** on the `easy-waf-api` host).
- **Pros:** no local database file; quick to start.
- **Cons:** depends on external service and network; per-IP HTTP calls (with in-memory cache).

## MaxMind (GeoLite2-Country.mmdb)

- Fully **offline** after the file is on disk.
- Set **`geoip_provider`** to **`maxmind`** and **`geoip_mmdb_path`** to the absolute path of **`GeoLite2-Country.mmdb`** (e.g. `/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb`).
- The API process opens the database with [`maxminddb-golang`](https://github.com/oschwald/maxminddb-golang); **`POST /api/v1/geoip/reload`** hot-swaps the reader after you replace the file (see script below).

### Installing GeoLite2

1. Create a **MaxMind** account and generate a **license key**: [License keys](https://www.maxmind.com/en/accounts/current/license-key).
2. Download **GeoLite2 Country** (`.tar.gz`) from the MaxMind portal or use the permalink flow in **`scripts/update-geoip-db.sh`** (requires **`MAXMIND_LICENSE_KEY`**).
3. Place **`GeoLite2-Country.mmdb`** on the appliance (recommended: **`/var/lib/easy-waf/geoip/`**).
4. In the UI **Security → GeoIP**, choose provider **maxmind**, set **MMDB path**, use **Validate (8.8.8.8)** (uses `probe_mmdb_path` without saving), then **Save GeoIP settings**.

If **GeoIP is enabled** and provider is **maxmind**, the API rejects settings save when **`geoip_mmdb_path`** is empty.

### Switching ipinfo → maxmind

1. Install the `.mmdb` file and note the absolute path.
2. **Security → GeoIP**: set provider to **maxmind**, fill **MMDB path**, **Save**.
3. Run **Apply** (or IPBL sync) so batch maps are regenerated using the local database.

### Scheduled updates

MaxMind updates GeoLite2 weekly. Use cron with the bundled script:

```bash
# Wednesday 03:00 — adjust path to your clone or install location
0 3 * * 3 /opt/easy-waf/scripts/update-geoip-db.sh >>/var/log/easy-waf-geoip-update.log 2>&1
```

Export **`MAXMIND_LICENSE_KEY`**. Optionally set **`EASY_WAF_ADMIN_TOKEN`** so the script calls **`POST /api/v1/geoip/reload`** after copying the new file (clears lookup cache and reloads the MMDB in memory).

Environment variables for **`scripts/update-geoip-db.sh`**:

| Variable | Required | Meaning |
|----------|----------|---------|
| `MAXMIND_LICENSE_KEY` | yes | MaxMind license key for the download URL |
| `EASY_WAF_GEOIP_DIR` | no | Destination directory (default `/var/lib/easy-waf/geoip`) |
| `EASY_WAF_API_URL` | no | API base (default `https://127.0.0.1:8443`) |
| `EASY_WAF_API_CA_CERT` | no | CA/certificate used to verify management HTTPS (default `$EASY_WAF_STATE_DIR/secrets/management.crt`) |
| `EASY_WAF_CURL_INSECURE` | no | Set to `1` only for explicit recovery with TLS verification disabled |
| `EASY_WAF_ADMIN_TOKEN` | no | If set, triggers **`/api/v1/geoip/reload`** |

## Real-time lookup vs batch map

| Mode | When | Mechanism |
|------|------|-------------|
| **Real-time** | `GET /api/v1/geoip/lookup?ip=…` from the UI or automation | Uses current provider + in-memory TTL cache (`geoip_cache_ttl`). Optional **`nocache=1`** bypasses cache for one request. For MaxMind path checks before save, use **`probe_mmdb_path=/path/to.mmdb`**. |
| **Batch** | Apply / IPBL sync with GeoIP enabled | Resolves many blacklist CIDRs (and per-app rules) through the same provider; writes HAProxy **`.map`** files used at the edge. |

Batch mode avoids per-request HTTP to ipinfo during traffic; MaxMind batch reads are local mmap lookups.

## API reference

- `GET /api/v1/geoip/providers` — `{ name, available, mmdb_path? }[]` for **ipinfo** / **maxmind** (maxmind `available` if path exists and is a regular file).
- `GET /api/v1/geoip/lookup?ip=…` — `nocache=1`, **`probe_mmdb_path=…`** (temporary MaxMind path for validation).
- `POST /api/v1/geoip/reload` — body optional `{ "mmdb_path": "…" }`; requires **`geoip_provider=maxmind`**; reloads MMDB and clears the lookup cache.

See also **`docs/ARCHITECTURE.md`** (GeoIP flow) and **`docs/DEPLOYMENT.md`** (state directory layout).
