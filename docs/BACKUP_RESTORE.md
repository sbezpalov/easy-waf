# Backup and restore

Full appliance backup includes:

1. **PostgreSQL** — `pg_dump` in **custom** format (`-Fc`) → `easywaf.dump` inside the archive (role-agnostic restore with `pg_restore --no-owner`).
2. **`/var/lib/easy-waf`** — state tree (HAProxy generated configs, revisions, certs, ACME webroot, secrets, …) under `state/` in the archive.
3. **`/etc/easy-waf`** — including `easy-waf.env` under `etc/` in the archive.
   The installer's temporary `easy-waf.env.rotation.*` and legacy
   `easy-waf.env.new-db-password` recovery files stay on the appliance.

Everything is packed into a **single gzip tarball**: `easy-waf-backup-YYYYMMDD-HHMMSS.tar.gz` (format **v1**; see `MANIFEST.txt` inside).

## Backup

Run as **root** (reads `/etc/easy-waf`, runs `pg_dump`):

```bash
cd /path/to/easy-waf
sudo bash scripts/backup.sh
```

Writes **`./easy-waf-backup-<timestamp>.tar.gz`** in the current directory and prints **absolute path** and **size** (`du -h`).

Use an output directory you trust. The archive is built in a private temporary
directory on the output filesystem, with mode `0600`, then published by rename.
An existing output is replaced only after successful packing; final symlinks are
replaced rather than followed, and other hardlink names keep their old contents.
Failed packing leaves the previous backup intact. Cleanup removes only this
run's temporary directories; existing `<output>.partial` files are left alone.

The script checks the output path and creates its parent directory before
pausing services. It checks `easy-waf-api` and `easy-waf-acmed` and confirms both are
stopped before running `pg_dump`. It aborts if systemd cannot report or stop
the writers. The script resumes the services it paused after copying the dump,
state and configuration into private staging, before compressing or publishing
the archive. Cleanup resumes paused services if capture fails. HAProxy keeps
serving the last applied configuration during the pause. If a writer fails to
resume, the script still attempts to publish the captured archive, reports its
path if publication succeeds, and exits nonzero.

Only one backup or restore invocation can own that pause. A nonblocking `flock` on the
existing `/etc/easy-waf` directory is held through writer recovery, packing and
rotation. An overlapping manual or timer run fails before
touching services or invoking `pg_dump`; retry after the active backup finishes.
The lock is shared across output/state paths and systemd's private `/tmp`.
Restore takes the same lock before archive extraction and retains it through
replacement and service startup. A competing backup or restore fails before
service/database access; retry after the active operation finishes.
Manual service starts and factory reset do not take this lock; avoid them during
either operation.

Custom output path:

```bash
sudo bash scripts/backup.sh /var/backups/easy-waf-$(date +%Y%m%d).tar.gz
```

Environment:

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_STATE_DIR` | `/var/lib/easy-waf` | State tree to archive |
| `EASY_WAF_ENV_FILE` | `/etc/easy-waf/easy-waf.env` | Source of the database setting for both `pg_dump` and the archive |

Backup captures the env file before stopping writers. An alternate file
contributes its last `DATABASE_URL` entry. The archive stores that entry in
`etc/easy-waf.env` alongside the other canonical appliance settings. Restore
uses this file for both the database restore and subsequent edge Apply.

For an archive made by an older backup with an alternate env file, verify
that its archived `etc/easy-waf.env` identifies the intended database
before running restore.

Requires **`pg_dump`**, **`pg_restore`** and **`psql`** (PostgreSQL client packages with
libpq), **Python 3** with its standard library, and **`flock`** (`util-linux`).
Backup and restore use a temporary mode-0600 libpq service file to keep the
connection string out of the client arguments. The file is removed with the
private staging directory. Values that do not fit libpq's service-file
format use the corresponding libpq environment variable where one exists.
An option with neither representation produces an error.

For development, `make test-backup-publication` exercises the real backup with
dummy data and fake database/service commands in a disposable Linux Docker
container, including overlapping invocations and safe archive publication.
Prepare `ubuntu:24.04` with `docker pull ubuntu:24.04`, or select an
existing Ubuntu image using `EASY_WAF_BACKUP_TEST_IMAGE`. The test runs offline,
with a read-only source mount and private config tmpfs; it does not back up or
stop services on the host. The nightly E2E workflow runs this regression.

## Scheduled backups

The package installs **`easy-waf-backup.timer`** and enables it once, on the first install or the upgrade that brings it. A standalone first DEB install schedules it at boot. The full `install.sh` starts an enabled timer after provisioning and starting the appliance. Disable it with `sudo systemctl disable --now easy-waf-backup.timer` to opt out across packaged upgrades and installer reruns. Every day at about 03:30 (randomized by up to 30 minutes; a missed run happens at the next boot) `easy-waf-backup.service` runs, as root:

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
sudo easy-waf-restore /var/backups/easy-waf-20260415-180000.tar.gz
```

The Debian package includes this command and its shared parser; no source checkout
or script download is needed. Install the matching appliance
package and PostgreSQL prerequisites before restoring on a new OS. For a source
installation or an older package without the command, use
`sudo bash scripts/restore.sh /path/to/backup.tar.gz` from the matching checkout.

### Restoring an older schema after an upgrade

Use the pre-upgrade package and its matched database, state and configuration
archive. Stop the appliance writers and scheduled backups before changing the
database or package. Preserve the current package and a new matched archive so
you can return to the current state.

Restore the older archive into an empty, dedicated database reachable through
the archived `DATABASE_URL`. Ask the database administrator to provision it with
the required owner and access. For a local appliance database with an unchanged
connection string, one option is to park the current database under a different
name and create an empty database at the original name. Keep the parked database
until recovery is verified. Do not rename or replace a shared database.

Install the matched package with the appliance writers stopped, then run its
packaged restore command. The restore's `pg_restore --clean` only drops objects
listed in the archive. Restoring an older dump into the upgraded database can
leave newer tables or functions behind even if the older application starts.
Verify the restored migration level, live HTTPS and service health before
resuming scheduled backups.

### What the restore command does

Steps:

1. Requires `flock` and acquires the shared backup/restore lock on `/etc/easy-waf`.
2. Extracts the archive privately, checks the required directories and
   nonempty `DATABASE_URL` in the backed-up env, and reads the dump's table of
   contents with `pg_restore --list`. Runs `SELECT 1` with the archived
   connection settings before stopping
   **`easy-waf-api`**, **`easy-waf-acmed`**, and **`easy-waf-hostd`**.
   Checks their initial state and confirms they have stopped before starting
   `pg_restore` or replacing files. If stopping or verification fails, restore
   aborts and attempts to resume only the services that were running or starting.
3. Runs **`pg_restore --single-transaction --clean --if-exists --no-owner --no-acl`**
   into the database from **`DATABASE_URL`** in the archived configuration.
   If `pg_restore` fails, the script preserves existing files and keeps the
   appliance services stopped. Verify the database outcome before restarting
   services, especially after a connection loss.
4. **Wipes** `EASY_WAF_STATE_DIR` and `/etc/easy-waf` contents, then restores **`state/`** and **`etc/`** (replace, not merge-over) so orphan PEMs, DNS env, rollback/staging and edge tokens cannot mix with the restored DB.
5. **`chown`**: `easy-waf:easy-waf` on state; **`root:easy-waf`** and **`0640`** on files under `/etc/easy-waf`, except secrets: **`root:root 0600`** on `easy-waf.env` and **`easy-waf:easy-waf 0600`** on other `*.env` files (DNS credentials).
6. **`restorecon`** is skipped on Ubuntu (AppArmor, not SELinux).
7. Runs **`easy-waf-admin apply-edge`** locally to regenerate HAProxy config and reload HAProxy (unless skipped). Restore does not depend on management HTTPS or a bearer token; the legacy automation token cannot satisfy API step-up.
8. Starts **`easy-waf-hostd`**, **`easy-waf-api`**, and **`easy-waf-acmed`**.

After restore on a new image, confirm polkit + HAProxy drop-in (package `postinst` installs both):

```bash
test -f /etc/polkit-1/rules.d/99-easy-waf-haproxy.rules
systemctl cat haproxy.service | grep -F /var/lib/easy-waf/haproxy/haproxy.cfg
sudo bash scripts/smoke-appliance.sh
```

Environment:

| Variable | Default | Meaning |
|----------|---------|--------|
| `EASY_WAF_STATE_DIR` | `/var/lib/easy-waf` | Restore target for state |
| `EASY_WAF_ADMIN_BIN` | `/usr/sbin/easy-waf-admin` | Console CLI used for apply |
| `EASY_WAF_SKIP_APPLY` | `0` | Set to **`1`** to skip `easy-waf-admin apply-edge` |

If file replacement fails after the database restore, the script reports
whether it was replacing state or configuration and leaves the appliance
services stopped. Keep the archive and complete file recovery before starting
the services.

If Apply is requested and fails, the admin command is unavailable, or a systemd
reload or start command fails, restore exits nonzero after attempting all three
service starts. The restored database and files are already in place. Keep the
archive, check the reported errors and finish recovery before treating the
appliance as ready. A successful exit confirms the requested commands returned
success. Verify the services and traffic separately.

If Apply failed, run it manually after fixing the reported database, render,
validation or reload problem:

```bash
sudo /usr/sbin/easy-waf-admin apply-edge \
  -env-file /etc/easy-waf/easy-waf.env \
  -state-dir /var/lib/easy-waf \
  -label restore-manual
```

Validate HAProxy:

```bash
sudo haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg
```

(Adjust path if `haproxy.cfg` is overridden in settings.)

## End-to-end test (optional)

**Destructive** (runs **factory-reset**, wipes DB and state, then restores). Requires a working appliance, **`curl`**, **`psql`**, and an admin panel account. On a TTY the script prompts for the username and password without echoing the password. For unattended runs, set **`EASY_WAF_E2E_USERNAME`**, **`EASY_WAF_E2E_PASSWORD`**, and, when applicable, **`EASY_WAF_E2E_TOTP_CODE`**. The legacy automation token cannot perform the step-up-protected writes exercised here. If `internal/haproxy/testdata/golden/certs/bundle-a.pem` is absent, the script generates a throwaway self-signed certificate directly under the appliance state directory (or use **`EASY_WAF_E2E_CERT_PEM`**); it does not modify the source tree. A successful run removes its test application, certificate, temporary backup and PEM, then re-applies the original edge state.

```bash
cd /path/to/easy-waf
sudo RUN_BACKUP_RESTORE_E2E=1 bash scripts/test-backup-restore.sh
```

For an unattended run, inject the credentials through the execution environment rather than storing them in `easy-waf.env`:

```bash
sudo --preserve-env=EASY_WAF_E2E_USERNAME,EASY_WAF_E2E_PASSWORD,EASY_WAF_E2E_TOTP_CODE \
  RUN_BACKUP_RESTORE_E2E=1 bash scripts/test-backup-restore.sh
```

Without **`RUN_BACKUP_RESTORE_E2E=1`**, the script exits **0** immediately (safe for accidental invocations).

If a run fails after creating its backup, the script **keeps the recovery archive** and prints its path. By default it remains in a private temporary directory; set **`EASY_WAF_E2E_BACKUP_PATH`** to an unused path outside the appliance state tree on persistent storage when recovery must survive a reboot. Restore it manually with `scripts/restore.sh` after diagnosing the failure. The archive contains the E2E application and certificate as well as the original data. Only a fully successful verification and cleanup removes the archive.

The E2E driver reads only `DATABASE_URL` from `EASY_WAF_ENV_FILE` as literal
data. Backup and factory reset use the same private copy of that entry. The
driver checks that the panel saved the test application in the selected
database before starting the backup or reset. Test options and operator
credentials come from the invoking environment or the prompts above. File
entries cannot change the selected state directory or recovery flags.

The driver uses private header files for panel session and confirmation tokens.
It discards those files and the authentication response even when it retains a
recovery archive. Authentication failure messages include the HTTP status.

`make test-backup-restore-workflow` exercises JSON requests, literal DSN handling,
env isolation and recovery-archive retention with mocked appliance commands. It
runs without root, PostgreSQL or systemd and is included in `make verify`; it does
not replace the live destructive E2E test.

## Legacy archives

Older one-off `tar` layouts (only `/var/lib/easy-waf` without `easywaf.dump` / `MANIFEST.txt`) are **not** supported by `restore.sh` — re-backup with the current `backup.sh` or restore files and DB manually.

## Operations notes

- Take backups **while** services are running only if your PostgreSQL workload tolerates a concurrent `pg_dump` (default custom format is consistent for restore).
- After restore on a **new** host, check **`DATABASE_URL`**, TLS paths, and **`CROWDSEC_*`** in `easy-waf.env` before going to production.
- See also [ARCHITECTURE.md](ARCHITECTURE.md) (revisions, apply pipeline) and [OPERATIONS.md](OPERATIONS.md).

Restoration extracts into a private "0700" temporary directory. Within that
parent it preserves archived group read/traverse permissions for HAProxy while
masking group write and access for others. Archived "0700" directories and
"0600" secret files remain private; ownership is assigned by the appliance.

Candidate-specific installed-command serialization and recovery checks are recorded
in [the 74b0df7 acceptance report](release-evidence/1.6.1-restore-lock-74b0df7.md).
