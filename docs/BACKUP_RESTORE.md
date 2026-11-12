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

The script **stops `easy-waf-api` and `easy-waf-acmed`** for the dump/archive window so PostgreSQL and on-disk secrets/certs stay consistent, then starts them again (including on failure). HAProxy keeps serving the last applied edge config during the pause.

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

## Scheduled backups

The package installs **`easy-waf-backup.timer`** and enables it once, on the first install or on the upgrade that brings it (disable it with `sudo systemctl disable --now easy-waf-backup.timer` and it stays off across upgrades). Every day at about 03:30 (randomized by up to 30 minutes; a missed run happens at the next boot) `easy-waf-backup.service` runs, as root:

```bash
/usr/share/easy-waf/scripts/backup.sh --dir /var/backups/easy-waf --keep 7
```

It writes `easy-waf-backup-<timestamp>.tar.gz` (0600) into the directory (created 0700), then deletes all but the 7 newest archives with that name pattern. Other files there are left alone, and a failed run leaves no partial archive. Set these in `/etc/easy-waf/easy-waf.env` to change it:

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_BACKUP_DIR` | `/var/backups/easy-waf` | Where archives go. Use a mounted NAS share or a second disk: a backup on the same disk does not survive the disk. |
| `EASY_WAF_BACKUP_KEEP` | `7` | Archives kept; `0` keeps all. |

Run one now with `sudo systemctl start easy-waf-backup.service` (or `sudo easy-waf-backup --dir /var/backups/easy-waf --keep 7`), check the last result with `systemctl status easy-waf-backup.service` and the schedule with `systemctl list-timers easy-waf-backup.timer`. Each archive holds TLS keys, the JWT secret and `DATABASE_URL`: protect copies taken off the box accordingly.

## Restore

Run as **root**. Pass the path to a backup produced by `scripts/backup.sh` (v1).

```bash
sudo bash scripts/restore.sh /var/backups/easy-waf-20260415-180000.tar.gz
```

Steps:

1. Stops **`easy-waf-api`**, **`easy-waf-acmed`**, and **`easy-waf-hostd`**.
2. Extracts the archive to a temp directory.
3. **`pg_restore --single-transaction --clean --if-exists --no-owner --no-acl`** into the database from **`DATABASE_URL`** in the **backed-up** `etc/easy-waf.env` (must still be valid on this host). A failed restore leaves the database unchanged and **does not** replace on-disk state.
4. **Wipes** `EASY_WAF_STATE_DIR` and `/etc/easy-waf` contents, then restores **`state/`** and **`etc/`** (replace, not merge-over) so orphan PEMs, DNS env, rollback/staging and edge tokens cannot mix with the restored DB.
5. **`chown`**: `easy-waf:easy-waf` on state; **`root:easy-waf`** and **`0640`** on files under `/etc/easy-waf`, except secrets: **`root:root 0600`** on `easy-waf.env` and **`easy-waf:easy-waf 0600`** on other `*.env` files (DNS credentials).
6. **`restorecon`** is skipped on Ubuntu (AppArmor, not SELinux).
7. Starts **`easy-waf-hostd`**, **`easy-waf-api`**, and **`easy-waf-acmed`**.
8. **`POST /api/v1/apply`** with **`Authorization: Bearer $EASY_WAF_ADMIN_TOKEN`** (from the shell environment **or** from the restored `easy-waf.env` after it is sourced) to regenerate HAProxy config and reload HAProxy (unless skipped).
9. Restarts **`easy-waf-api`** and **`easy-waf-acmed`**.

Environment:

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_STATE_DIR` | `/var/lib/easy-waf` | Restore target for state |
| `EASY_WAF_ENV_FILE` | `/etc/easy-waf/easy-waf.env` | Used after restore to source tokens |
| `EASY_WAF_API_BASE` | `https://127.0.0.1:8443` | Base URL for apply; override for an explicitly enabled legacy HTTP listener |
| `EASY_WAF_API_CA_CERT` | `$EASY_WAF_STATE_DIR/secrets/management.crt` | CA/certificate used to verify management HTTPS |
| `EASY_WAF_ADMIN_TOKEN` | *(from env file)* | Bearer for apply; export before restore if not in env file |
| `EASY_WAF_SKIP_APPLY` | `0` | Set to **`1`** to skip the apply API call when the management listener is unavailable |
| `EASY_WAF_CURL_INSECURE` | `0` | Explicit recovery-only override for `curl --insecure`; prefer a matching API URL and `EASY_WAF_API_CA_CERT` |

If apply fails, run manually after fixing connectivity:

```bash
sudo systemctl restart easy-waf-api easy-waf-acmed
curl --cacert /var/lib/easy-waf/secrets/management.crt -fsS \
  -X POST https://127.0.0.1:8443/api/v1/apply \
  -H "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"label":"restore-manual"}'
```

Validate HAProxy:

```bash
sudo haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg
```

(Adjust path if `haproxy.cfg` is overridden in settings.)

## End-to-end test (optional)

**Destructive** (runs **factory-reset**, wipes DB and state, then restores). Requires a working appliance with **`EASY_WAF_ADMIN_TOKEN`** in `easy-waf.env` and **`curl`**. If `internal/haproxy/testdata/golden/certs/bundle-a.pem` is absent, the script writes a throwaway self-signed certificate there with `openssl` (or use **`EASY_WAF_E2E_CERT_PEM`**).

```bash
cd /path/to/easy-waf
sudo RUN_BACKUP_RESTORE_E2E=1 bash scripts/test-backup-restore.sh
```

Without **`RUN_BACKUP_RESTORE_E2E=1`**, the script exits **0** immediately (safe for accidental invocations).

Both restore scripts still accept an explicit `http://127.0.0.1:8000` API base for appliances where legacy loopback HTTP is intentionally enabled. Their default follows the secure HTTPS-only management policy.

## Legacy archives

Older one-off `tar` layouts (only `/var/lib/easy-waf` without `easywaf.dump` / `MANIFEST.txt`) are **not** supported by `restore.sh` — re-backup with the current `backup.sh` or restore files and DB manually.

## Operations notes

- Take backups **while** services are running only if your PostgreSQL workload tolerates a concurrent `pg_dump` (default custom format is consistent for restore).
- After restore on a **new** host, check **`DATABASE_URL`**, TLS paths, and **`CROWDSEC_*`** in `easy-waf.env` before going to production.
- See also [ARCHITECTURE.md](ARCHITECTURE.md) (revisions, apply pipeline) and [OPERATIONS.md](OPERATIONS.md).
