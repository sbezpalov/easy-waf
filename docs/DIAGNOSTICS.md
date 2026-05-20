# Diagnostics bundles

Two ways to collect a support bundle:

| Method | Command / entry | Privileges | Best for |
|--------|------------------|--------------|----------|
| **Root script** | `sudo bash scripts/diagnostics.sh` (repo) or **`sudo /usr/sbin/easy-waf-diagnostics`** (after `install.sh`) | **root** | Full host picture: `ss -tlnp` PIDs, `nft list ruleset`, all journals, `psql` from real `DATABASE_URL`, AppArmor status. |
| **API / UI** | `POST /api/v1/diagnostics/bundle` or **Dashboard → Download diagnostics** | Runs as **`easy-waf`** (systemd service) | Quick export from the browser; secrets still masked; some commands may be empty or show permission errors. |

Default tarball path for the **root** script: `/tmp/easy-waf-diag-YYYYMMDD-HHMMSS.tar.gz` (override with first argument).

## What is inside (both bundles, roughly)

Layout is similar (tar tree with `MANIFEST.txt`, `system/`, `systemctl/`, `logs/`, `config/`, `validation/`, `sql/`, `firewall/`):

- **MANIFEST.txt** — UTC time, hostname, version (`EASY_WAF_VERSION` when set), bundle source (`api` vs script).
- **system/** — `uname`, `/etc/os-release`, `hostnamectl`, `free`, `df`, `uptime`, `ss -tlnp`, `aa-status` (best-effort from API).
- **systemctl/** — `systemctl status` and `is-enabled` for: `easy-waf-api`, `easy-waf-acmed`, `haproxy`, `crowdsec`, `fail2ban`, `nftables`.
- **logs/** — last 500 lines / 24h from `journalctl` for `easy-waf-api`, `easy-waf-acmed`, `haproxy`.
- **config/easy-waf.env.masked** — copy of `/etc/easy-waf/easy-waf.env` with:
  - `DATABASE_URL` — password replaced with `***MASKED***` (postgres / postgresql URLs).
  - `CROWDSEC_LAPI_KEY`, `EASY_WAF_JWT_SECRET`, `EASY_WAF_ADMIN_TOKEN` — full value replaced with `***MASKED***`.
- **config/haproxy.cfg** — live HAProxy config from settings path (default under `EASY_WAF_STATE_DIR`).
- **config/crt-list-filenames.txt** — **only basenames** of paths from `crt-list.txt` (no PEM contents).
- **validation/** — `haproxy -vv` and `haproxy -c -f …` output.
- **sql/config_revisions.txt** — last **5** revisions: `id`, `haproxy_sha256` (as `sha256`), `at` (as `created_at`). Root script uses `psql`; API uses the application DB pool (same data on a normal appliance).
- **firewall/** — `nft list ruleset` when available (includes `/etc/nftables/easy-waf.nft` when loaded).

## What is NOT included

- **Private keys**, PEM bodies, full paths to secrets on disk (only crt-list **basenames**).
- **Unmasked** `DATABASE_URL`, CrowdSec keys, JWT secret, admin token (see masking above).
- **Full CrowdSec / fail2ban** journals unless `journalctl` is allowed for the API user (often only partial from UI bundle).
- **PostgreSQL dumps**, `acmed` internal state beyond logs, browser session tokens, other tenants’ data.
- **Arbitrary files** under `/var/lib/easy-waf` except `haproxy/haproxy.cfg` and crt-list name list (not the whole state tree).

## API vs root script (important)

The **`easy-waf-api`** unit uses **`NoNewPrivileges=true`**, so the API **cannot** elevate via `sudo` to run the root script. The **Download diagnostics** button builds a bundle **in-process** as user `easy-waf`. If something is missing (e.g. `journalctl` denied, `nft` needs root), the corresponding file may be short or contain an error message.

For vendor/support hand-off when in doubt, prefer:

```bash
sudo /usr/sbin/easy-waf-diagnostics
```

or from a git checkout:

```bash
sudo bash scripts/diagnostics.sh
```

Then attach the resulting `/tmp/easy-waf-diag-*.tar.gz`.
