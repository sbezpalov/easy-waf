# Emergency CLI (`easy-waf-admin`)

Root-only maintenance tool installed as `/usr/sbin/easy-waf-admin` (see `Makefile` / `scripts/install.sh`).

Requires **`DATABASE_URL`** in the environment (e.g. `export $(grep -v '^#' /etc/easy-waf/easy-waf.env | xargs)` before running, or `sudo -E` with env set) — **except** for **`print-enrollment`**, **`reset-appliance -bootstrap-credentials`**, **`management-config`**, and **`reset-control-panel-access`**, which read **`DATABASE_URL`** from **`/etc/easy-waf/easy-waf.env`** (or **`-env-file`**) when it is not passed as **`-database-url`** and not exported.

## `print-enrollment`

Print the one-time operator enrollment secret from **`$EASY_WAF_STATE_DIR/secrets/enrollment`** (mode **0600**) to **stdout only**. Run as root on the appliance console (or another local trusted channel). Do not paste the secret into journald, tickets, or the audit log.

```bash
sudo /usr/sbin/easy-waf-admin print-enrollment
```

Then enroll at **`POST /api/v1/auth/enroll`** (or the UI) with `{ "secret", "username", "password" }`. The file is deleted after a successful enrollment.

## `doctor`

Runs a full health and self-diagnostic check across the appliance components:

1. **Storage & Permissions**: Validates `/var/lib/easy-waf` and `secrets/` directory permissions, checks available filesystem space and inodes.
2. **Database (PostgreSQL)**: Tests connection, validates `schema_migrations` records, and counts configured entities (applications, certs, operators).
3. **HAProxy Edge**: Verifies binary presence, validates edge configuration syntax (`haproxy -c`), and tests stats socket responsiveness.
4. **Services (systemd)**: Checks active status of `easy-waf-api`, `easy-waf-acmed`, `easy-waf-hostd`, `haproxy`, `crowdsec`, and `fail2ban`.
5. **GeoIP**: Checks MaxMind MMDB file presence and freshness.
6. **TLS Certificates**: Checks expiration dates for all active certificates in the certs directory.

```bash
# Human-readable output
sudo /usr/sbin/easy-waf-admin doctor

# Machine-readable JSON output (for monitoring / CI scripts)
sudo /usr/sbin/easy-waf-admin doctor -json
```

Exits with `0` if all checks pass or only non-critical warnings exist, and `1` if any critical errors are detected.

## Automated appliance reset (dev / lab)

**`-bootstrap-credentials`** (run as **root** via `sudo`): one command to align PostgreSQL and easy-waf after a broken or unknown DB password:

1. Reads **`DATABASE_URL`** from **`/etc/easy-waf/easy-waf.env`** (override path with **`-env-file`**).
2. Runs **`ALTER USER … PASSWORD`** as the OS **`postgres`** superuser (`runuser -u postgres psql` — local cluster only; host in the URL must be **`127.0.0.1`**, **`localhost`**, **`::1`**, or empty for socket).
3. Generates two random **19-character** secrets (alphanumeric): new **database role password** and new **`EASY_WAF_ADMIN_TOKEN`**, writes them into the env file.
4. Truncates configuration tables and clears generated state under **`/var/lib/easy-waf`** (same as a normal reset).
5. Writes **`/root/easy-waf-bootstrap-credentials.txt`** (mode **0600**) with the new **`DATABASE_URL`** and token — **copy, then delete** the file.

The **GUI operator** is **not** recreated as `admin`/`admin`. After **`easy-waf-api`** starts, print the one-time secret with **`easy-waf-admin print-enrollment`** and enroll.

```bash
sudo /usr/sbin/easy-waf-admin reset-appliance -confirm RESET -bootstrap-credentials
sudo systemctl restart easy-waf-api easy-waf-acmed
sudo cat /root/easy-waf-bootstrap-credentials.txt
# after saving secrets to your vault:
sudo rm -f /root/easy-waf-bootstrap-credentials.txt
```

Optional: **`-credentials-out /path/to/file.txt`** (default **`/root/easy-waf-bootstrap-credentials.txt`**).

**Remote PostgreSQL** is not supported by **`-bootstrap-credentials`** (host must be local). On external DB appliances, rotate the role password on the DB server, update **`DATABASE_URL`** manually, then run **`reset-appliance -confirm RESET`** without **`-bootstrap-credentials`**.

## `management-config`

Inspect or adjust **management bind addresses** (`EASY_WAF_LISTEN_HTTP` / `EASY_WAF_LISTEN_HTTPS` in **`easy-waf.env`**) and the **application-level GUI/API source allowlist** (`management_allowed_cidrs` in the database — same semantics as the Settings UI / API).

**Read-only** (prints env-derived listeners, stored CIDRs, and the **effective** allowlist used when the stored list is empty):

```bash
sudo /usr/sbin/easy-waf-admin management-config
```

**Examples — write changes** (always **`sudo systemctl restart easy-waf-api.service`** afterwards so a running process reloads env and DB-backed settings):

```bash
# Listen on all interfaces (LAN / RFC1918 + nftables as in install.sh)
sudo /usr/sbin/easy-waf-admin management-config -listen-lan

# Loopback only (use SSH port-forward to reach the UI)
sudo /usr/sbin/easy-waf-admin management-config -listen-loopback

# Custom bind addresses (non-loopback HTTP also needs EASY_WAF_ALLOW_INSECURE_HTTP=1)
sudo /usr/sbin/easy-waf-admin management-config -listen-http 127.0.0.1:8000 -listen-https 0.0.0.0:8443

# Replace allowlist (comma-separated CIDRs; at least one required)
sudo /usr/sbin/easy-waf-admin management-config \
  -management-cidrs '127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'

# Reset CIDR allowlist to built-in defaults (RFC1918 + loopback)
sudo /usr/sbin/easy-waf-admin management-config -default-management-cidrs
```

Flags: **`-env-file`**, **`-state-dir`**, **`-database-url`** (same meaning as on **`reset-appliance`**). Do not combine **`-listen-loopback`** with **`-listen-lan`** or with **`-listen-http` / `-listen-https`**. Do not combine **`-default-management-cidrs`** with **`-management-cidrs`**.

## `reset-control-panel-access`

Use when the management UI/API is unreachable because of **IP allowlist** or **bind address** mistakes.

```bash
sudo /usr/sbin/easy-waf-admin reset-control-panel-access
sudo systemctl restart easy-waf-api.service
```

(Alternatively: `sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin reset-control-panel-access'` — not required; **`DATABASE_URL`** is read from **`/etc/easy-waf/easy-waf.env`** by default.)

Effects:

1. Sets **`management_allowed_cidrs`** in the database to the **default** list (loopback + RFC1918 — same as `config.DefaultManagementCIDRs()`).
2. Writes **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`** and **`EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`** into `/etc/easy-waf/easy-waf.env`, removes deprecated **`EASY_WAF_LISTEN`** (path overridable with `-env-file`).

Review **nftables** (`/etc/nftables/easy-waf.nft`) afterwards if management ports are too open.

## `reset-appliance` (preferred)

**Destructive:** same as legacy `factory-reset` — truncates configuration tables and clears generated state under the state directory (`haproxy/`, `revisions/`, `certs/`, `acme/`, `secrets/`). PostgreSQL schema is kept.

Confirmation must be the literal token **`RESET`** (avoids accidental one-flag typos):

```bash
sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin reset-appliance -confirm RESET'
sudo systemctl restart easy-waf-api.service easy-waf-acmed.service
```

With a one-shot DSN when **`DATABASE_URL` in the env file is wrong** (do not source `easy-waf.env` for `DATABASE_URL` in that case, or export the correct URL after sourcing):

```bash
sudo /usr/sbin/easy-waf-admin reset-appliance -confirm RESET \
  -database-url 'postgres://easywaf:REAL_PASSWORD@127.0.0.1:5432/easywaf?sslmode=disable'
```

Optional state path (default `/var/lib/easy-waf`):

```bash
/usr/sbin/easy-waf-admin reset-appliance -state-dir /var/lib/easy-waf -confirm RESET
```

### Wrong password in `easy-waf.env` (cannot connect to PostgreSQL)

If **`DATABASE_URL`** in the env file is stale but you know the real password (e.g. after `ALTER USER` as `postgres`), run the wipe **without** sourcing the broken URL — pass a one-shot DSN (quote carefully; URL-encode `@` and other special characters in the password):

```bash
sudo /usr/sbin/easy-waf-admin factory-reset -i-am-sure=true \
  -database-url 'postgres://easywaf:REAL_PASSWORD@127.0.0.1:5432/easywaf?sslmode=disable'
```

Then update **`/etc/easy-waf/easy-waf.env`** so **`DATABASE_URL`** matches that password, or services will fail again on restart.

### `Usage:` does not list `reset-appliance`

The **`/usr/sbin/easy-waf-admin`** binary is older than the repo. Rebuild and reinstall:

```bash
cd ~/easy-waf && git pull && make build
sudo install -m 0755 -t /usr/sbin dist/easy-waf-admin
```

After a normal wipe (without **`-bootstrap-credentials`**), ensure **`DATABASE_URL`** in `/etc/easy-waf/easy-waf.env` still matches the PostgreSQL **`easywaf`** role password (install may have rotated it — see `scripts/lib/db-password.sh`). On first **`easy-waf-api`** start with an empty **`users`** table, a one-time enrollment secret is written to **`$EASY_WAF_STATE_DIR/secrets/enrollment`** (mode **0600**). Print it with **`easy-waf-admin print-enrollment`** and enroll in the UI — there is no default `admin`/`admin` password.

With **`-bootstrap-credentials`**, **`DATABASE_URL`** is already updated; only restart services and handle the credentials file as above.

## `factory-reset` (legacy)

Same effect as **`reset-appliance`**. Kept for scripts and older docs.

```bash
sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin factory-reset -i-am-sure=true'
sudo systemctl restart easy-waf-api.service easy-waf-acmed.service
```

Optional **`-database-url`** works the same as for **`reset-appliance`** (see above).

**`-bootstrap-credentials`** is also accepted on **`factory-reset`** (with **`-i-am-sure=true`**).

## Environment bypass (lockout)

If you can edit `/etc/easy-waf/easy-waf.env` but need immediate API access without changing the DB:

```bash
# EASY_WAF_BYPASS_MGMT_ACL=1
```

Restart **`easy-waf-api`**. Remove this after recovery. See `configs/defaults/easy-waf.env.example`.
