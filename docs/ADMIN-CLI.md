# Emergency CLI (`easy-waf-admin`)

Root-only maintenance tool installed as `/usr/sbin/easy-waf-admin` (see `Makefile` / `scripts/install.sh`).

Requires **`DATABASE_URL`** in the environment (e.g. `export $(grep -v '^#' /etc/easy-waf/easy-waf.env | xargs)` before running, or `sudo -E` with env set).

## `reset-control-panel-access`

Use when the management UI/API is unreachable because of **IP allowlist** or **bind address** mistakes.

```bash
sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin reset-control-panel-access'
sudo systemctl restart easy-waf-api.service
```

Effects:

1. Sets **`management_allowed_cidrs`** in the database to the **default** list (loopback + RFC1918 — same as `config.DefaultManagementCIDRs()`).
2. Writes **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`** and **`EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`** into `/etc/easy-waf/easy-waf.env`, removes deprecated **`EASY_WAF_LISTEN`** (path overridable with `-env-file`).

Review **firewalld** afterwards if you had opened 8443/tcp broadly on the public zone.

## `reset-appliance` (preferred)

**Destructive:** same as legacy `factory-reset` — truncates configuration tables and clears generated state under the state directory (`haproxy/`, `revisions/`, `certs/`, `acme/`, `secrets/`). PostgreSQL schema is kept.

Confirmation must be the literal token **`RESET`** (avoids accidental one-flag typos):

```bash
sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin reset-appliance -confirm RESET'
sudo systemctl restart easy-waf-api.service easy-waf-acmed.service
```

Optional state path (default `/var/lib/easy-waf`):

```bash
/usr/sbin/easy-waf-admin reset-appliance -state-dir /var/lib/easy-waf -confirm RESET
```

After a wipe, ensure **`DATABASE_URL`** in `/etc/easy-waf/easy-waf.env` still matches the PostgreSQL **`easywaf`** role password (install may have rotated it — see `scripts/lib/db-password.sh`). On first **`easy-waf-api`** start with an empty **`users`** table, the default operator **`admin` / `admin`** is recreated — change the password in the UI.

## `factory-reset` (legacy)

Same effect as **`reset-appliance`**. Kept for scripts and older docs.

```bash
sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin factory-reset -i-am-sure=true'
sudo systemctl restart easy-waf-api.service easy-waf-acmed.service
```

## Environment bypass (lockout)

If you can edit `/etc/easy-waf/easy-waf.env` but need immediate API access without changing the DB:

```bash
# EASY_WAF_BYPASS_MGMT_ACL=1
```

Restart **`easy-waf-api`**. Remove this after recovery. See `configs/defaults/easy-waf.env.example`.
