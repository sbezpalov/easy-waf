# AGENTS.md — easy-waf

> **Источник истины для всех AI-инструментов и людей в этом репозитории.**
> Файл читают нативно Cursor, Google Antigravity/Gemini и другие AGENTS-совместимые
> инструменты. Тонкие редиректы (`.cursorrules`, `CLAUDE.md`, `GEMINI.md`,
> `PERPLEXITY.md`) дополняют, но не отменяют эти правила. **Прочитай целиком перед работой.**

## Language
- **Default:** English — chat replies, UI strings, commit/PR text, and new docs.
- **Alternative:** Russian when the user explicitly asks for it (see `.cursor/rules/020-language.mdc`).

## 1. Проект
**Easy Home WAF** — self-hosted appliance: защищённый reverse proxy / домашний WAF
для публикации локальных сервисов (Home Assistant, Frigate, Nextcloud, Wirenboard и т.п.)
через единый HAProxy-edge. Даёт автоматические TLS-сертификаты (ACME), защиту от атак
(CrowdSec через SPOE, Fail2Ban, IP-блоклисты, GeoIP) и локальную веб-панель управления.
Пользователи — владельцы домашних/SME-серверов, публикующие сервисы наружу без ручной
настройки HAProxy. Ценность — «plug-and-play» edge-безопасность на одной VM.

## 2. Стек
- **Язык:** Go (модуль `github.com/easy-waf/easy-waf`, go 1.22, `CGO_ENABLED=0`).
- **HTTP/API:** chi (`go-chi/chi/v5`), JWT (`golang-jwt/jwt/v5`), embedded static UI (`internal/webui/dist`).
- **БД:** PostgreSQL (драйвер `jackc/pgx/v5`) — единый source of truth; SQL-миграции в `internal/store/migrations`.
- **ACME/TLS:** Lego (`go-acme/lego/v4`) — HTTP-01 и DNS-01 (Cloudflare, CloudNS, Route53, webhook).
- **GeoIP:** MaxMind MMDB (`oschwald/maxminddb-golang`, `maxmind/mmdbwriter`).
- **Метрики:** Prometheus (`prometheus/client_golang`), дашборд Grafana в `configs/grafana`.
- **Edge/инфра:** HAProxy 3.x, CrowdSec + SPOA, Fail2Ban, nftables, systemd, netplan.
- **Платформа:** **Ubuntu 24.04 LTS** (appliance OS). Разработка часто на Windows 11 / WSL.
- **Сборка/CI:** Makefile (`make ci` = lint + test + verify), GitHub Actions (`ci.yml`, `release.yml`), golangci-lint, Docker Compose (только dev-PostgreSQL).

## 3. Структура
| Каталог | Назначение |
|---|---|
| `cmd/easy-waf-api/` | Management REST API + встроенная UI, рендер/apply HAProxy |
| `cmd/easy-waf-acmed/` | ACME-воркер (Lego): выпуск и обновление сертификатов |
| `cmd/easy-wafd/` | Legacy-энтрипойнт → тот же код, что `easy-waf-api` |
| `cmd/easy-waf-admin/` | Emergency CLI: сброс доступа к панели, factory reset, apply edge |
| `cmd/easy-waf-hostd/` | Host-management daemon (network, nftables, apt) |
| `internal/` | store (PostgreSQL), haproxy, acme, api, ipbl, admin, webui и др. |
| `internal/store/migrations/` | SQL-схема БД |
| `internal/webui/dist/` | Встроенная статика UI |
| `configs/` | Дефолты и примеры (haproxy, crowdsec-spoe, dns-*.env, grafana) |
| `scripts/` | install, install-interactive, upgrade, backup/restore, check-linux-artifacts |
| `packaging/` | systemd-юниты для api + acmed |
| `docs/` | Архитектура, security, ACME/DNS, CrowdSec, Fail2Ban, IPBL, GeoIP и др. |
| `examples/` | Примеры определений приложений (Home Assistant, Wirenboard) |
| `docker-compose.yml` | Только dev-PostgreSQL |

## 4. Статус / текущий приоритет
- **Версия:** `1.4.1` (файл `VERSION` задаёт номер релиза и документов; релизы — по тегу `v*` через `release.yml`).
- **Архитектура C (текущая):** PostgreSQL как единый source of truth; сервисы `easy-waf-api` (API + UI + HAProxy render/apply) и `easy-waf-acmed` (ACME-воркер).
- Целевая платформа зафиксирована: **только Ubuntu 24.04 LTS**, HAProxy 3.x, nftables, systemd.
- Соответствие требований `prompts.md` ↔ коду отслеживается в `docs/PROMPTS_ALIGNMENT.md` (MVP gap matrix).

## 5. Как вносить изменения (агент)
- Работай через план: декомпозируй задачу и покажи шаги ДО исполнения.
- Human-in-the-loop: для необратимых операций и правок прод-данных — остановись и спроси.
- Формируй артефакты (diff, список изменённых файлов, план отката) до применения.
- Изменения атомарные; объясняй ЧТО и ПОЧЕМУ.
- Новый код — с тестами; задача не «done» при падающих тестах/линте.

## 6. Безопасность (NEVER)
- Прод (appliance-VM) не редактируется напрямую: доставка через git → сборка (`make build`) → установка/upgrade скриптами на Ubuntu 24.04 LTS.
- Секреты (пароли, ключи, токены, ACME-креды, DNS-провайдеры, `*.env`, локальные конфиги) — не коммитить и не выводить; в репозитории только `*.example` (см. `configs/**/*.example`).
- Деструктивные операции над боевой БД (PostgreSQL) / сертификатами / edge-конфигом HAProxy — только с явным подтверждением и прогоном на копии; помни, что БД — единый source of truth.
- **NEVER** коммитить Windows-бинарники: не добавляй `dist/*.exe` / `dist/*.dll` (проверяет `scripts/check-linux-artifacts.sh`).
- **NEVER** ломать line endings: `scripts/**/*.sh` — только **Unix (LF)** (CRLF валит bash на Linux; см. `.gitattributes`).
- Не ослабляй edge-политику без причины: nftables (edge 80/443, management 8000/8443 только из RFC1918), CrowdSec/SPOE, Fail2Ban; первичная учётка панели создаётся через одноразовый enrollment secret (не `admin/admin`).
- Не коммить артефакты из `.gitignore`; при отсутствии `bash`/`go` в среде — явно сообщи, а не обходи проверки.

## 7. Definition of Done
- [ ] Изменение локально; секреты не попали в код/коммит.
- [ ] Тесты/линт зелёные; при необходимости проверено на staging.
- [ ] Diff отревьюен, есть план отката.

## Раскладка инструментов
Артефакты — в `.ai/artifacts/` (кросс) и `.<инструмент>/artifacts/`. Детали — `.ai/README.md`.

<!-- Инициализировано init-ai-tooling.sh v2 (2026-07-05). -->
