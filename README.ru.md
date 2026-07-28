# Easy Home WAF

[English](README.md) | **Русский**

[![CI](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml)
[![Release](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml/badge.svg)](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml)

Self-hosted **защищённый reverse proxy / домашний WAF-appliance** для публикации локальных сервисов (Home Assistant, Frigate, Nextcloud, …) через единый HAProxy-edge с ACME, CrowdSec (SPOE), Fail2Ban и локальной панелью управления.

**Целевая платформа:** только **Ubuntu 24.04 LTS**, HAProxy 3.x (пакет дистрибутива), systemd, хостовый firewall **nftables**; сеть — netplan.

**Релиз / инсталлятор:** корневой файл [`VERSION`](VERSION) задаёт номер для GitHub Releases и документов; релизы собирает workflow [`release.yml`](.github/workflows/release.yml) (тег `v*`, см. [`CHANGELOG.md`](CHANGELOG.md)).

## Документация

Документы в `docs/` ведутся на **английском** (канон). Ниже — краткие описания на русском.

| Документ | Описание |
|----------|----------|
| [docs/DEV_HOST.md](docs/DEV_HOST.md) | Пилот-хост по SSH: **`waf-dev`**, Remote SSH, `.vscode/settings.json` |
| [docs/PROMPTS_ALIGNMENT.md](docs/PROMPTS_ALIGNMENT.md) | Требования [prompts.md](prompts.md) ↔ код (MVP gap matrix) |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Компоненты, потоки данных, жизненный цикл конфига, риски |
| [docs/QUICKSTART.md](docs/QUICKSTART.md) | Установка и первое приложение |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Инсталлятор (apt), OVF/OVA, релизы |
| [docs/HOST-API.md](docs/HOST-API.md) | Host management API (сеть, nftables, apt, …) |
| [docs/SECURITY.md](docs/SECURITY.md) | Hardening, AppArmor, nftables, секреты, чеклист |
| [docs/ACME.md](docs/ACME.md) | Сертификаты и DNS-провайдеры |
| [docs/DNS01.md](docs/DNS01.md) | DNS-01: Cloudflare, CloudNS (по умолчанию), Route53, webhook |
| [docs/CROWDSEC.md](docs/CROWDSEC.md) | SPOE, bouncer, логи |
| [docs/FAIL2BAN.md](docs/FAIL2BAN.md) | Статус Fail2Ban и unban через API/UI |
| [docs/IPBL.md](docs/IPBL.md) | IP blacklist: локальный + внешние фиды → карта HAProxy |
| [docs/GEOIP.md](docs/GEOIP.md) | GeoIP: ipinfo vs MaxMind MMDB, обновления, batch vs lookup API |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Типичные сбои |
| [docs/ADMIN-CLI.md](docs/ADMIN-CLI.md) | Аварийно: сброс доступа к панели, factory reset |
| [docs/VM-REQUIREMENTS.md](docs/VM-REQUIREMENTS.md) | ESXi / QEMU–KVM: vCPU, RAM, диск, NIC |

## Архитектура C (текущая)

- **PostgreSQL** — единый source of truth (SME / будущий HA / реплики).
- **`easy-waf-api`** — REST API, встроенный UI, рендер/apply HAProxy.
- **`easy-waf-acmed`** — ACME-воркер (Lego HTTP-01): выпуск и продление сертификатов.
- **`easy-wafd`** — legacy-энтрипойнт; тот же код, что у `easy-waf-api`.

**IPBL**: локальные + опциональные внешние блоклисты → объединённая map-файл для HAProxy (`docs/IPBL.md`).

## Быстрая сборка (разработчик, Linux или WSL)

```bash
cd easy-waf
export DATABASE_URL='postgres://easywaf:easywaf@127.0.0.1:5432/easywaf?sslmode=disable'
# docker compose up -d   # поднимает PostgreSQL из docker-compose.yml
make build
./dist/easy-waf-api -state-dir ./data -listen-http 127.0.0.1:8000 -listen-https 127.0.0.1:8443
# ./dist/easy-waf-acmed   # опционально; задайте EASY_WAF_STATE_DIR и тот же DATABASE_URL
```

**Не коммитьте** Windows-артефакты `.exe` / `.dll`. После правок кода запускайте **`make ci`** (`go vet`, `golangci-lint`, `go test ./...`, `bash scripts/check-linux-artifacts.sh`) или как минимум `bash scripts/check-linux-artifacts.sh && go test ./...`. Для шага lint установите [golangci-lint](https://golangci-lint.run/welcome/install/). Cursor подхватывает [`.cursor/rules/easy-waf-verify-after-edits.mdc`](.cursor/rules/easy-waf-verify-after-edits.mdc), чтобы агент прогонял проверки после правок.

**Shell-скрипты:** только **Unix (LF)**. Bash на Linux падает на CRLF (`$'\r': command not found`). В репозитории задано `scripts/**/*.sh text eol=lf` в `.gitattributes`; на Windows — `git config core.autocrlf input` или режим «LF» в редакторе.

**Установка appliance (VM Ubuntu 24.04 LTS):** `sudo bash scripts/install.sh` — полный стек: HAProxy, **PostgreSQL**, **CrowdSec + SPOA** (LAPI bootstrap по умолчанию), **fail2ban**, **nftables** (edge **80/443** + management **8000/8443** из RFC1918), **`easy-waf-api`** / **`easy-waf-acmed`**. UI слушает **`0.0.0.0:8000` / `0.0.0.0:8443`**; устаревшие bind на конкретный IP в env правятся при переустановке. Внешняя БД: `EASY_WAF_INSTALL_POSTGRES=0`. См. [QUICKSTART.md](docs/QUICKSTART.md).

После клона выполните **`go mod tidy`** (создаёт `go.sum`), затем **`make build`**. Панель: вход **`admin` / `admin`** при первой установке, затем смена пароля по запросу.

Для опционального **CrowdSec** + SPOA и дополнительных вопросов используйте **`scripts/install-interactive.sh`** (политика bind там тоже настраивается).

## Структура репозитория

```
cmd/easy-waf-api/    # Management API + UI
cmd/easy-waf-acmed/  # ACME-воркер (Lego)
cmd/easy-wafd/       # Alias-энтрипойнт → тот же код, что easy-waf-api
internal/            # store (PostgreSQL), haproxy, acme, api, ipbl, …
internal/store/migrations/  # SQL-схема
internal/webui/dist/ # Встроенная статика UI
configs/             # Примеры дефолтов (haproxy, фрагменты crowdsec)
scripts/             # install, upgrade, backup, restore, check-linux-artifacts
packaging/           # systemd-юниты для api + acmed
docs/                # Архитектура и гайды (английский)
examples/            # Примеры определений приложений
docker-compose.yml   # Только dev-PostgreSQL
```

## Лицензия

Apache-2.0 (см. LICENSE).
