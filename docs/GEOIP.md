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

### Installing GeoLite2 from the UI (no shell access needed)

1. Create a **MaxMind** account and generate a **license key**: [License keys](https://www.maxmind.com/en/accounts/current/license-key).
2. Download **GeoLite2 Country** from the MaxMind portal — either the `.tar.gz` as published or an unpacked `.mmdb`.
3. In the UI **Security → GeoIP** select provider **maxmind**, then **Upload database** → pick the file → **Upload & install**.
4. The path field is filled in automatically. Press **Save GeoIP settings** so `geoip_mmdb_path` persists, then **Apply** so batch maps are regenerated.

What the appliance does with the uploaded file:

- The format is detected from the file content (gzip magic), **not** from the file name. A `.tar.gz` is scanned for its `*.mmdb` member; member paths inside the archive are ignored entirely, so a crafted archive cannot write outside the GeoIP directory.
- The upload lands in `<state>/geoip/` under a name derived from the database's own metadata (`GeoLite2-Country.mmdb`, `GeoLite2-City.mmdb`). The request cannot choose the destination.
- Before anything is replaced, the uploaded file is opened as a MaxMind database, its type is checked for country data, and it must answer a lookup for `8.8.8.8`. Only then is it renamed into place — **a rejected upload leaves the running database untouched**.
- If the provider is already **maxmind** *and* `geoip_mmdb_path` already points at the file that was just installed (the normal case for a weekly refresh), the reader is hot-swapped and the lookup cache cleared — no restart, no `POST /geoip/reload`. That is reported as `"reloaded": true`.
- On a first install the path is not configured yet, so the response is `"reloaded": false` with an `activate_hint`: the runtime resolves its reader from `geoip_mmdb_path`, so the database only goes live after you **Save GeoIP settings**. The UI fills the path field for you.
- Accepted size is capped at **128 MiB** (decompressed), and each install is recorded in the audit log as `geoip_database_uploaded`.

### Installing GeoLite2 from a shell

1. Place **`GeoLite2-Country.mmdb`** on the appliance (recommended: **`/var/lib/easy-waf/geoip/`**, owned by `easy-waf`).
2. In the UI **Security → GeoIP**, choose provider **maxmind**, set **MMDB path**, use **Validate (8.8.8.8)** (uses `probe_mmdb_path` without saving), then **Save GeoIP settings**.

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
- `POST /api/v1/geoip/database` — **raw** request body (`application/octet-stream`): a `.mmdb` file or a MaxMind `.tar.gz`. Installs it into `<state>/geoip/` after validation and hot-swaps the reader when the provider is maxmind. Returns `{ path, database_type, build_epoch, node_count, ip_version, size_bytes, probe_ip, probe_country, reloaded }`. Rejects with **400** and keeps the previous database if the payload is not a usable country database. This is the only route exempt from the global 4 MiB body limit; it applies its own 128 MiB cap.

  ```bash
  curl -f --cacert /var/lib/easy-waf/secrets/management.crt \
    -H "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" \
    -H "X-Requested-With: XMLHttpRequest" \
    -H "Content-Type: application/octet-stream" \
    --data-binary @GeoLite2-Country.tar.gz \
    https://127.0.0.1:8443/api/v1/geoip/database
  ```

See also **`docs/ARCHITECTURE.md`** (GeoIP flow) and **`docs/DEPLOYMENT.md`** (state directory layout).
