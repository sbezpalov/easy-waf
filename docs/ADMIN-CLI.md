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

## `factory-reset`

**Destructive:** truncates configuration tables and clears generated state under the state directory.

```bash
sudo sh -c 'set -a; . /etc/easy-waf/easy-waf.env; set +a; /usr/sbin/easy-waf-admin factory-reset --i-am-sure'
sudo systemctl restart easy-waf-api.service easy-waf-acmed.service
```

Reconfigure **`DATABASE_URL`**, sign-in (**`admin` / `admin`** is recreated on next `easy-waf-api` start when the `users` table is empty), and applications from scratch.

## Environment bypass (lockout)

If you can edit `/etc/easy-waf/easy-waf.env` but need immediate API access without changing the DB:

```bash
# EASY_WAF_BYPASS_MGMT_ACL=1
```

Restart **`easy-waf-api`**. Remove this after recovery. See `configs/defaults/easy-waf.env.example`.
