# Easy Home WAF

**English** | [Русский](README.ru.md)

[![CI](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml)
[![Release](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml/badge.svg)](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml)

Self-hosted **secure reverse proxy / home WAF appliance** for publishing local services (Home Assistant, Frigate, Nextcloud, …) through a single HAProxy edge with ACME, CrowdSec (SPOE), Fail2Ban, and a local management UI.

**Target platform:** **Ubuntu 24.04 LTS** only, HAProxy 3.x (distro build), systemd, **nftables** host firewall; netplan for networking.

**Release / installer:** the root [`VERSION`](VERSION) file sets the number for GitHub releases and docs; releases are built by workflow [`release.yml`](.github/workflows/release.yml) (tag `v*`, see [`CHANGELOG.md`](CHANGELOG.md)).

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/DEV_HOST.md](docs/DEV_HOST.md) | Pilot host over SSH: **`waf-dev`**, Remote SSH, `.vscode/settings.json` |
| [docs/PROMPTS_ALIGNMENT.md](docs/PROMPTS_ALIGNMENT.md) | [prompts.md](prompts.md) requirements ↔ code (MVP gap matrix) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, config lifecycle, risks |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Install and first application |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Installer (apt), OVF/OVA, releases |
| [docs/HOST-API.md](docs/HOST-API.md) | Host management API (network, nftables, apt, …) |
| [docs/SECURITY.md](docs/SECURITY.md) | Hardening, AppArmor, nftables, secrets, checklist |
| [docs/ACME.md](docs/ACME.md) | Certificates and DNS providers |
| [docs/DNS01.md](docs/DNS01.md) | DNS-01: Cloudflare, CloudNS (default), Route53, webhook |
| [docs/CROWDSEC.md](docs/CROWDSEC.md) | SPOE, bouncer, logs |
| [docs/FAIL2BAN.md](docs/FAIL2BAN.md) | Fail2Ban status and unban via API/UI |
| [docs/IPBL.md](docs/IPBL.md) | IP blacklist: local + external feeds → HAProxy map |
| [docs/GEOIP.md](docs/GEOIP.md) | GeoIP: ipinfo vs MaxMind MMDB, updates, batch vs lookup API |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common failures |
| [docs/ADMIN-CLI.md](docs/ADMIN-CLI.md) | Emergency: reset control panel access, factory reset |
| [docs/VM-REQUIREMENTS.md](docs/VM-REQUIREMENTS.md) | ESXi / QEMU–KVM: vCPU, RAM, disk, NICs |

## Architecture C (current)

- **PostgreSQL** — single source of truth (SME / future HA / replicas).
- **`easy-waf-api`** — REST API, embedded UI, HAProxy render/apply.
- **`easy-waf-acmed`** — ACME (Lego HTTP-01) issuance and renewal worker.
- **`easy-wafd`** — legacy entrypoint; same code path as `easy-waf-api`.

**IPBL**: local + optional external blocklists → merged map file for HAProxy (`docs/IPBL.md`).

## Quick build (developer, Linux or WSL)

```bash
cd easy-waf
export DATABASE_URL='postgres://easywaf:easywaf@127.0.0.1:5432/easywaf?sslmode=disable'
# docker compose up -d   # starts PostgreSQL from docker-compose.yml
make build
./dist/easy-waf-api -state-dir ./data -listen-http 127.0.0.1:8000 -listen-https 127.0.0.1:8443
# ./dist/easy-waf-acmed   # optional; set EASY_WAF_STATE_DIR, same DATABASE_URL
```

Do **not** commit Windows `.exe` / `.dll` artifacts. After code changes run **`make ci`** (`go vet`, `golangci-lint`, `go test ./...`, `bash scripts/check-linux-artifacts.sh`) or at least `bash scripts/check-linux-artifacts.sh && go test ./...`. Install [golangci-lint](https://golangci-lint.run/welcome/install/) for the lint step. Cursor loads [`.cursor/rules/easy-waf-verify-after-edits.mdc`](.cursor/rules/easy-waf-verify-after-edits.mdc) so the agent is instructed to run this after edits.

**Shell scripts:** must use **Unix (LF)** line endings. Bash on Linux fails on CRLF (`$'\r': command not found`). The repo sets `scripts/**/*.sh text eol=lf` in `.gitattributes`; on Windows use `git config core.autocrlf input` or your editor’s “LF” mode.

**Appliance install (Ubuntu 24.04 LTS VM):** `sudo bash scripts/install.sh` — full stack: HAProxy, **PostgreSQL**, **CrowdSec + SPOA** (LAPI bootstrap by default), **fail2ban**, **nftables** (edge **80/443** + management **8000/8443** from RFC1918), **`easy-waf-api`** / **`easy-waf-acmed`**. Management UI binds **`0.0.0.0:8000` / `0.0.0.0:8443`**; stale per-IP binds in env are fixed on reinstall. External DB: `EASY_WAF_INSTALL_POSTGRES=0`. See [QUICKSTART.md](docs/QUICKSTART.md).

After clone, run **`go mod tidy`** (generates `go.sum`) then **`make build`**. Management UI: sign in as **`admin` / `admin`** on first install and change the password when prompted.

Use **`scripts/install-interactive.sh`** for optional **CrowdSec** + SPOA and extra prompts (bind policy still configurable there).

## Repository layout

```
cmd/easy-waf-api/    # Management API + UI
cmd/easy-waf-acmed/  # ACME worker (Lego)
cmd/easy-wafd/       # Alias entrypoint → same as easy-waf-api
internal/            # store (PostgreSQL), haproxy, acme, api, ipbl, …
internal/store/migrations/  # SQL schema
internal/webui/dist/ # Embedded static UI
configs/             # Sample defaults (haproxy, crowdsec snippets)
scripts/             # install, upgrade, backup, restore, check-linux-artifacts
packaging/           # systemd units for api + acmed
docs/                # Architecture and guides
examples/            # Sample app definitions
docker-compose.yml   # Dev PostgreSQL only
```

## License

Apache-2.0 (see LICENSE).
