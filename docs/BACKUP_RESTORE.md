# Backup and restore

Full appliance backup includes:

1. **PostgreSQL** — `pg_dump` in **custom** format (`-Fc`) → `easywaf.dump` inside the archive (role-agnostic restore with `pg_restore --no-owner`).
2. **`/var/lib/easy-waf`** — state tree (HAProxy generated configs, revisions, certs, ACME webroot, secrets, …) under `state/` in the archive.
3. **`/etc/easy-waf`** — including `easy-waf.env` under `etc/` in the archive.

Everything is packed into a **single gzip tarball**: `easy-waf-backup-YYYYMMDD-HHMMSS.tar.gz` (format **v1**; see `MANIFEST.txt` inside).

## Backup

Run as **root** (reads `/etc/easy-waf`, runs `pg_dump`):

```bash
cd /path/to/easy-waf
sudo bash scripts/backup.sh
```

Writes **`./easy-waf-backup-<timestamp>.tar.gz`** in the current directory and prints **absolute path** and **size** (`du -h`).

Custom output path:

```bash
sudo bash scripts/backup.sh /var/backups/easy-waf-$(date +%Y%m%d).tar.gz
```

Environment:

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_STATE_DIR` | `/var/lib/easy-waf` | State tree to archive |
| `EASY_WAF_ENV_FILE` | `/etc/easy-waf/easy-waf.env` | Source of `DATABASE_URL` for `pg_dump` |

Requires **`pg_dump`** on `PATH` (PostgreSQL client packages).

## Restore

Run as **root**. Pass the path to a backup produced by `scripts/backup.sh` (v1).

```bash
sudo bash scripts/restore.sh /var/backups/easy-waf-20260415-180000.tar.gz
```

Steps:

1. Stops **`easy-waf-api`** and **`easy-waf-acmed`**.
2. Extracts the archive to a temp directory.
3. **`pg_restore --clean --if-exists --no-owner --no-acl`** into the database from **`DATABASE_URL`** in the **backed-up** `etc/easy-waf.env` (must still be valid on this host).
4. Restores **`state/`** → `EASY_WAF_STATE_DIR` and **`etc/`** → `/etc/easy-waf` (merged via tar extract).
5. **`chown`**: `easy-waf:easy-waf` on state; **`root:easy-waf`** and **`0640`** on files under `/etc/easy-waf`.
6. **`restorecon`** is skipped on Ubuntu (AppArmor, not SELinux).
7. Starts **`easy-waf-api`** / **`easy-waf-acmed`**.
8. **`POST /api/v1/apply`** with **`Authorization: Bearer $EASY_WAF_ADMIN_TOKEN`** (from the shell environment **or** from the restored `easy-waf.env` after it is sourced) to regenerate HAProxy config and reload HAProxy (unless skipped).
9. Restarts **`easy-waf-api`** and **`easy-waf-acmed`**.

Environment:

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_STATE_DIR` | `/var/lib/easy-waf` | Restore target for state |
| `EASY_WAF_ENV_FILE` | `/etc/easy-waf/easy-waf.env` | Used after restore to source tokens |
| `EASY_WAF_API_BASE` | `http://127.0.0.1:8000` | Base URL for apply |
| `EASY_WAF_ADMIN_TOKEN` | *(from env file)* | Bearer for apply; export before restore if not in env file |
| `EASY_WAF_SKIP_APPLY` | `0` | Set to **`1`** to skip the apply HTTP call (e.g. API not listening on HTTP) |
| `EASY_WAF_CURL_INSECURE` | *(unset)* | Set to **`1`** in **`scripts/test-backup-restore.sh`** only (not restore.sh) for `curl -k` in tests |

If apply fails, run manually after fixing connectivity:

```bash
sudo systemctl restart easy-waf-api easy-waf-acmed
curl -fsS -X POST http://127.0.0.1:8000/api/v1/apply \
  -H "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"restore-manual"}'
```

Validate HAProxy:

```bash
sudo haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg
```

(Adjust path if `haproxy.cfg` is overridden in settings.)

## End-to-end test (optional)

**Destructive** (runs **factory-reset**, wipes DB and state, then restores). Requires a working appliance with **`EASY_WAF_ADMIN_TOKEN`** in `easy-waf.env`, **`curl`**, and repo test PEM at `internal/haproxy/testdata/golden/certs/bundle-a.pem` (or set **`EASY_WAF_E2E_CERT_PEM`**).

```bash
cd /path/to/easy-waf
sudo RUN_BACKUP_RESTORE_E2E=1 bash scripts/test-backup-restore.sh
```

Without **`RUN_BACKUP_RESTORE_E2E=1`**, the script exits **0** immediately (safe for accidental invocations).

## Legacy archives

Older one-off `tar` layouts (only `/var/lib/easy-waf` without `easywaf.dump` / `MANIFEST.txt`) are **not** supported by `restore.sh` — re-backup with the current `backup.sh` or restore files and DB manually.

## Operations notes

- Take backups **while** services are running only if your PostgreSQL workload tolerates a concurrent `pg_dump` (default custom format is consistent for restore).
- After restore on a **new** host, check **`DATABASE_URL`**, TLS paths, and **`CROWDSEC_*`** in `easy-waf.env` before going to production.
- See also [ARCHITECTURE.md](ARCHITECTURE.md) (revisions, apply pipeline) and [OPERATIONS.md](OPERATIONS.md).
