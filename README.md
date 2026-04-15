# Easy Home WAF

[![CI](https://github.com/easy-waf/easy-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/easy-waf/easy-waf/actions/workflows/ci.yml)

Self-hosted **secure reverse proxy / home WAF appliance** for publishing local services (Home Assistant, Frigate, Nextcloud, …) through a single HAProxy edge with ACME, CrowdSec (SPOE), Fail2Ban, and a local management UI.

**Target platform:** AlmaLinux 10 or **Debian/Ubuntu** (22.04+ / 12+), HAProxy 3.x (distro build), systemd, firewalld; **SELinux Enforcing** on RHEL-family images.

**Release / installer:** корневой файл [`VERSION`](VERSION) задаёт номер для GitHub release и документов; для MVP зафиксировано **1.0.0-rc1** (см. [docs/PROMPTS_ALIGNMENT.md](docs/PROMPTS_ALIGNMENT.md) §9).

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/DEV_HOST.md](docs/DEV_HOST.md) | Пилот по SSH: хост **`waf-dev`**, Remote SSH, `.vscode/settings.json` |
| [docs/PROMPTS_ALIGNMENT.md](docs/PROMPTS_ALIGNMENT.md) | Требования [prompts.md](prompts.md) ↔ код (MVP gap matrix) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flow, config lifecycle, risks |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Install and first application |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Installer (dnf/apt), OVF/OVA, releases |
| [docs/SECURITY.md](docs/SECURITY.md) | Hardening, SELinux, secrets, checklist |
| [docs/ACME.md](docs/ACME.md) | Certificates and DNS providers |
| [docs/DNS01.md](docs/DNS01.md) | DNS-01: Cloudflare, CloudNS (default), Route53, webhook |
| [docs/CROWDSEC.md](docs/CROWDSEC.md) | SPOE, bouncer, logs |
| [docs/IPBL.md](docs/IPBL.md) | IP blacklist: local + external feeds → HAProxy map |
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

**Appliance install (Alma/RHEL or Debian/Ubuntu VM):** `sudo bash scripts/install.sh` — installs HAProxy stack, **PostgreSQL** (local DB by default), **firewalld** rules so the UI (**`http://<LAN-IP>:8443`**, bind `0.0.0.0:8443`) is reachable only from **RFC1918 + loopback**, provisions DB, starts **`easy-waf-api`** / **`easy-waf-acmed`**. External DB only: `EASY_WAF_INSTALL_POSTGRES=0`. See [QUICKSTART.md](docs/QUICKSTART.md).

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
configs/             # Sample defaults (haproxy, nginx optional, crowdsec snippets)
scripts/             # install, upgrade, backup, restore, check-linux-artifacts
packaging/           # systemd units for api + acmed
docs/                # Architecture and guides
examples/            # Sample app definitions
docker-compose.yml   # Dev PostgreSQL only
```

## License

Apache-2.0 (see LICENSE).
