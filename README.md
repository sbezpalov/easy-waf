# Easy Home WAF

**English** | [Русский](README.ru.md)

[![CI](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml)
[![Release](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml/badge.svg)](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A self-hosted **WAF and secure reverse proxy appliance** for publishing local
services — Home Assistant, Frigate, Nextcloud, Node-RED, Grafana — through a
single hardened HAProxy edge, managed from a local web UI instead of hand-edited
config files.

It is aimed at the person who has a homelab or a small office behind NAT, wants
two ports open instead of ten, and would rather not become a HAProxy expert to
get certificates, geo-filtering and bot blocking right.

## What it does

- **One edge for everything.** Each application gets a hostname, a backend and a
  security profile; HAProxy configuration is generated, validated with
  `haproxy -c` and reloaded — never hand-edited.
- **Per-application security layers**, switchable per host: rate limiting, basic
  WAF rules (SQLi/XSS/traversal), CrowdSec via SPOE, IP allow/block lists with
  external feeds, GeoIP country filtering, bot/User-Agent blocking, method and
  path restrictions, LAN-only paths. Presets range from *full protection* to
  *reverse-proxy-only*.
- **Certificates without ceremony.** ACME HTTP-01 and DNS-01 (Cloudflare, CloudNS,
  Route53, webhook), automatic renewal, TLS verification for HTTPS backends.
- **Host management from the same UI:** network and nftables with a **timed
  rollback**, so a bad firewall rule reverts itself instead of locking you out;
  system updates with a live log; services, journal, local accounts.
- **Operational safety:** every apply is a revision you can roll back to,
  privileged actions are audited, `easy-waf-admin doctor` diagnoses the appliance,
  and backup/restore covers database, state and configuration.

## Security posture

This is an appliance that terminates TLS at the edge of a network, so the design
assumes parts of it will be attacked and that one of them will eventually lose:

- `easy-waf-api` runs unprivileged (`NoNewPrivileges`, `ProtectSystem=strict`).
  Every privileged operation goes through **`easy-waf-hostd`**, a root broker on a
  unix socket that checks its peer with `SO_PEERCRED`, dispatches only allowlisted
  opcodes, and **re-validates every argument itself** — the threat model
  explicitly includes a compromised API.
- **No default password.** The first operator enrolls with a one-time CSPRNG
  secret readable only on the local console.
- Sessions carry a `session_version`: changing the password or signing out revokes
  every token already issued.
- Values that reach the generated configuration are validated **again at render
  time**, because a config-injection bug produces a file `haproxy -c` happily
  accepts.
- Outbound fetches (blocklist feeds, CrowdSec LAPI) re-check the resolved IP at
  dial time — closing DNS rebinding — and refuse redirects.
- Release artifacts are verified against `SHA256SUMS` before anything is unpacked.

The controls and the reasoning behind them: [docs/SECURITY.md](docs/SECURITY.md).
Reporting a vulnerability: [SECURITY.md](SECURITY.md).

## Requirements

- **Ubuntu 24.04 LTS** — the only supported platform, deliberately (see
  [CONTRIBUTING.md](CONTRIBUTING.md#what-this-project-is-and-is-not))
- root on the appliance, systemd, nftables
- PostgreSQL — installed for you by default, or point at an external one
- 2 vCPU / 2 GB RAM is comfortable; see [docs/VM-REQUIREMENTS.md](docs/VM-REQUIREMENTS.md)

## Install

On a fresh Ubuntu 24.04 VM:

```bash
git clone https://github.com/sbezpalov/easy-waf.git
cd easy-waf
sudo bash scripts/install.sh
```

This installs HAProxy, PostgreSQL, CrowdSec + SPOA bouncer, fail2ban and nftables
rules, then starts `easy-waf-api` and `easy-waf-acmed`. Binaries come from the
matching GitHub release when one exists — verified against `SHA256SUMS`, and the
installer refuses anything that fails verification — otherwise they are built from
source.

Then log in. There is no default password:

```bash
sudo easy-waf-admin print-enrollment      # one-time secret, printed locally
```

Open `https://<appliance-ip>:8443`, enroll, add your first application. Full
walkthrough: [docs/QUICKSTART.md](docs/QUICKSTART.md).

> Packaging is being reworked: a native `.deb` will replace clone-and-run as the
> primary path — see [ADR 0001](docs/adr/0001-packaging-and-installer.md).

## Documentation

**Start here**

| Doc | What is in it |
|-----|---------------|
| [QUICKSTART](docs/QUICKSTART.md) | Install, first login, first application |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Components, data flow, configuration lifecycle |
| [OPERATIONS](docs/OPERATIONS.md) | Day-2: manual validation, toggles, post-upgrade smoke test |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | When something does not work |

**Security and protection layers**

| Doc | What is in it |
|-----|---------------|
| [SECURITY](docs/SECURITY.md) | Hardening, privilege model, supply chain, checklist |
| [APPLICATION_SECURITY](docs/APPLICATION_SECURITY.md) · [SECURITY_PROFILES](docs/SECURITY_PROFILES.md) | Per-application layers and presets |
| [CROWDSEC](docs/CROWDSEC.md) · [FAIL2BAN](docs/FAIL2BAN.md) | Behavioural blocking |
| [IPBL](docs/IPBL.md) · [GEOIP](docs/GEOIP.md) | IP lists, external feeds, country filtering |

**Certificates, host, operations**

| Doc | What is in it |
|-----|---------------|
| [ACME](docs/ACME.md) · [DNS01](docs/DNS01.md) · [DNS](docs/DNS.md) | Issuance and renewal |
| [HOST-API](docs/HOST-API.md) | Network, nftables, updates, accounts |
| [BACKUP_RESTORE](docs/BACKUP_RESTORE.md) · [ADMIN-CLI](docs/ADMIN-CLI.md) | Backups and emergency recovery |
| [MONITORING](docs/MONITORING.md) · [DIAGNOSTICS](docs/DIAGNOSTICS.md) | Metrics and diagnostics |
| [DEPLOYMENT](docs/DEPLOYMENT.md) · [VM-REQUIREMENTS](docs/VM-REQUIREMENTS.md) | Rollout, OVF/OVA, sizing |
| [adr/](docs/adr/) | Architecture decision records |

## How it is built

```
cmd/easy-waf-api/     Management API + embedded UI, HAProxy render and apply
cmd/easy-waf-acmed/   ACME worker (Lego)
cmd/easy-waf-hostd/   Root broker: allowlisted privileged host operations
cmd/easy-waf-admin/   CLI: diagnostics, enrollment, emergency access recovery
internal/             store (PostgreSQL), haproxy, api, auth, acme, ipbl, geoip, …
scripts/              install, upgrade, backup/restore, appliance smoke test
packaging/systemd/    Unit files
docs/                 Guides and decision records
```

PostgreSQL is the single source of truth. The API renders HAProxy configuration
from it, validates, applies, and keeps every revision for rollback.

## Contributing

Bug reports, fixes and documentation corrections are welcome — start with
[CONTRIBUTING.md](CONTRIBUTING.md), which explains what is in scope and how to run
the same checks CI runs.

**Never report a security vulnerability in a public issue.** Use
[private reporting](SECURITY.md).

## Status

Used in production by its author on a home network; the interfaces documented here
are stable, and anything breaking goes through `CHANGELOG.md` with an upgrade note.
It is a young project maintained by one person — read
[docs/SECURITY.md](docs/SECURITY.md) before putting it in front of something you
cannot afford to lose, and keep backups (`scripts/backup.sh`).

## License

[Apache-2.0](LICENSE).
