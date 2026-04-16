# Соответствие `prompts.md` (Easy Home WAF)

**Последнее обновление:** 2026-04-16  
**Текущий VERSION:** 1.0.0 (см. корневой файл `VERSION`)  
**Сводка по строкам таблиц §2–§3:** Done — **17**, Partial — **3**, Missing — **1**, N/A — **0**

Этот документ **привязывает** требования из [prompts.md](../prompts.md) к коду и докам репозитория. Статусы: **Done** | **Partial** | **Missing** | **N/A** (вне MVP / перенесено).

Источник истины по реализации — **§7 Features** и проверка приёмки — **§9 Acceptance criteria**. Ниже в §2–§3 только компактный указатель со статусом и ссылкой `см. §7.*` / при необходимости на §9.

## §2 Goals — Core

| Требование | Статус | Где |
|------------|--------|-----|
| Публикация сервисов по доменам → backend | **Done** | см. **§7.1** |
| TLS на HAProxy (crt-list, сертификаты из ACME/DB, SNI, HTTP→HTTPS) | **Done** | см. **§7.1**, **§7.2**, **§7.3** |
| ACME выдача/продление | **Done** | см. **§7.2** |
| WebSocket (`Application.WebSocket`, `timeout tunnel`) | **Done** | см. **§7.3**; **§9** AC-09 |
| Единая точка входа HAProxy (`fe_http` / `fe_https`) | **Done** | см. **§7.3** |

## §2 Security

| Требование | Статус | Где |
|------------|--------|-----|
| Rate limit (stick-tables), per-app | **Done** | см. **§7.1a** |
| Базовый WAF (ACL), per-app | **Done** | см. **§7.1a** |
| CrowdSec + решения (LAPI, decisions в UI) | **Partial** | см. **§7.5** (нет unblock/ban в UI) |
| SPOE bouncer | **Done** | см. **§7.3**; шаблон `filter spoe` / `send-spoe-group`; `install.sh`, `docs/CROWDSEC.md` |
| Fail2Ban | **Partial** | установка в `install.sh`; оркестрация через API — нет |
| GeoIP + кэш (ipinfo, batch map, ACL) | **Done** | см. **§7.6** |

## §2 UX / Observability

| Требование | Статус | Где |
|------------|--------|-----|
| Web UI (LAN): 8 вкладок, dashboard | **Done** | см. **§7.7** |
| Сертификаты, логи, stats, health | **Done** | см. **§7.7**, **§7.8**; audit, `/health`, `/status` |
| Backup/restore | **Done** | **§9** AC-10; `scripts/backup.sh`, `restore.sh`, E2E `scripts/test-backup-restore.sh` |

## §3 Constraints

| Требование | Статус | Где |
|------------|--------|-----|
| Alma 10, systemd, firewalld, SELinux | **Done** | `scripts/install.sh`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md` |
| `haproxy -c` до reload | **Done** | см. **§7.3**; `internal/apply`, `internal/engine` |
| SPOE, WebSocket, SNI, redirect (golden + CI) | **Done** | см. **§7.3** |
| CrowdSec LAPI не через Lua | **Partial** | доки + SPOA пакет; см. **§7.5** |
| Генератор конфига, валидация, атомарный apply, rollback | **Done** | см. **§7.3**; **§9** AC-06 |
| GeoIP API + batch map + ACL | **Done** | см. **§7.6** |
| MaxMind MMDB как провайдер | **Missing** | Roadmap; заглушка `internal/geoip/maxmind.go` |

## §6 Repository structure (целевая схема в prompts)

| Путь в prompts | Факт в репо | Примечание |
|----------------|-------------|------------|
| `/internal/config` | `internal/config` | OK |
| `/internal/haproxy` | `internal/haproxy` | Шаблон встроен в `render.go` |
| `/internal/acme` | `internal/acme` | OK |
| `/internal/security` | нет отдельного пакета | см. `profiles`, `api/mgmtacl`, `auth` |
| `/internal/geoip` | `internal/geoip` | OK |
| `/internal/crowdsec` | `internal/crowdsec` | OK |
| `/internal/stats` | `internal/metrics` (HAProxy socket) | см. `GET /api/v1/stats/*` |
| `/web/frontend` | `internal/webui/dist` | Встраивается через `embed` |
| `/templates/*.tmpl` | внутри `render.go` | При желании вынести в файлы |
| `/tests` | точечные `*_test.go` + **golden** HAProxy в `internal/haproxy/testdata/golden/` | Нет отдельного дерева e2e |

## §7 Features

### 7.1 App publishing — **Done** (CRUD API + UI, профили, restricted paths, health path в модели)

### 7.1a Per-application security — **Done** (миграция `009_application_security.sql`, `Application.security`, пресеты `internal/profiles/modes.go`, HAProxy per-host ACL порядок, per-app GeoIP maps `geoip_app_*.map`, API `GET/PUT/PATCH /applications/{id}/security`, `POST …/security/mode`, `GET /security/modes`, audit `app_security_mode_changed`, UI карточки + Dashboard overview, golden `app-*` / `mixed-apps`, `docs/APPLICATION_SECURITY.md`)

### 7.2 ACME — **Done** (HTTP-01, DNS-01 провайдеры, renew worker, apply hook в `easy-waf-acmed`)

### 7.2a Global settings API — **Done** (`GET /api/v1/settings`; **`PATCH /api/v1/settings`** — частичный JSON, merge поверх текущих значений в памяти/DB; **`PUT /api/v1/settings`** — тот же merge, чтобы частичное тело не обнуляло пути/таймауты; поля `geoip_cache_ttl` и `acme_renewal_interval` в JSON как строки `time.ParseDuration`, например `"24h"`, `"30m"`, плюс приём числа наносекунд для старых снимков; UI сохраняет ACME через PATCH) — `internal/api/server.go`, `internal/config/settings_merge.go`, `internal/config/duration.go`, `internal/webui/dist/index.html`

### 7.3 HAProxy engine — **Done** (шаблон, checksum, validate, revisions/rollback, golden)

### 7.4 Security profiles — **Done** (имена из prompts: `balanced`, `strict`, `trusted-lan`, `public-app`, `home-assistant`) — `internal/profiles/profiles.go`, `docs/SECURITY_PROFILES.md`

### 7.5 CrowdSec — **Partial** (ping LAPI, decisions в UI; whitelist/unblock в UI — нет, `cscli` / LAPI)

### 7.6 GeoIP — **Done** (`internal/geoip`, `GET /api/v1/geoip/lookup`, `GET /api/v1/geoip/stats`, настройки `geoip_*`, миграция `007`, batch `geoip_enforce.map` + ACL в `render.go`, секция в UI)

### 7.7 UI страницы — **Done** (вкладки из §7 prompts + audit/logs, certificate summary)

### 7.8 Statistics — **Done** (`internal/metrics` — HAProxy `show stat` over Unix socket, cache 5s; API `GET /api/v1/stats/haproxy`, `GET /api/v1/stats/summary`; Dashboard traffic + backends, refresh 10s; `haproxy_stats_socket_path` + golden template)

## §8 Lessons learned

Зафиксировано в `docs/ARCHITECTURE.md`, `docs/CROWDSEC.md`, `internal/haproxy/render.go` (SNI, ws, валидация).

## §9 Acceptance criteria (MVP) — ТЗ v1.1 (AC-01 … AC-10)

Проверка по коду и скриптам (итерации A–D). **Partial** = поведение зависит от среды (NAT, DNS, пакет SPOA) или осознанно вынесено из UI.

| ID | Критерий | Статус | Проверка в репозитории |
|----|----------|--------|-------------------------|
| **AC-01** | Установка через `install.sh` на AlmaLinux 10 (полный цикл: пакеты, layout, env, PostgreSQL опционально, бинарники, systemd) | **Done** | `scripts/install.sh` — `dnf`/`apt`, `create_user_and_layout`, `install_env_file`, `systemctl enable --now easy-waf-api.service easy-waf-acmed.service` (флаг `EASY_WAF_ENABLE_SYSTEMD_UNITS`), юниты `packaging/systemd/*.service`, `WantedBy=multi-user.target` |
| **AC-02** | Добавление app через UI + Apply | **Done** | UI `#apps` → `POST /api/v1/applications`; `#config` → `POST /api/v1/apply`; `internal/api/server.go`, `internal/engine/engine.go` |
| **AC-03** | HTTPS-сертификат автоматически (ACME) | **Partial** | `cmd/easy-waf-acmed` — выдача/renew, после успеха `eng.Apply(ctx,"acme")`; нужны `ACME_EMAIL`, DNS/HTTP-01, worker запущен (`docs/ACME.md`) |
| **AC-04** | Доступ извне к опубликованному приложению | **Partial** | Рендер `fe_http`/`fe_https`, SNI, бэкенды по Host — **Done** в коде; маршрутизация WAN/NAT/port-forward — вне репозитория |
| **AC-05** | CrowdSec блокирует; HAProxy отдаёт 403 для запрещённого трафика | **Partial** | В шаблоне `filter spoe engine …` + ACL с `deny_status 403` (WAF, IPBL, GeoIP, UA); реакция на decision из SPOA — конфиг пакета bouncer + `docs/CROWDSEC.md` |
| **AC-06** | Apply + rollback | **Done** | `engine.Apply` / `Rollback`, ревизии в БД; `POST /revisions/{id}/rollback`; UI Config (таблица ревизий + кнопка) |
| **AC-07** | UI: apps, certs, blocked | **Done** | Вкладки Applications, Certificates (в т.ч. summary/actions), Security (IPBL, blocked UA), Dashboard |
| **AC-08** | Переживает reboot | **Done** | `systemctl enable` для api/acmed (и опционально CrowdSec); `Restart=on-failure` в unit-файлах |
| **AC-09** | WebSocket (например HA) | **Done** | `timeout tunnel` в defaults и для `websocket` в `internal/haproxy/render.go` |
| **AC-10** | Backup + restore | **Done** | `scripts/backup.sh`, `scripts/restore.sh`, `docs/BACKUP_RESTORE.md`, `scripts/test-backup-restore.sh` |

**SELinux (из §9 prompts):** не отключается скриптом; политика контекстов — в `docs/DEPLOYMENT.md` / `docs/SECURITY.md`. Статус: **Done** при следовании докам (на хосте).

## Roadmap (после MVP)

1. **Release pipeline (базово сделано):** [`.github/workflows/release.yml`](../.github/workflows/release.yml) — push тега `v*`, `make build`, tarball + `SHA256SUMS`, GitHub Release с текстом из `CHANGELOG.md`. Далее: подпись артефактов, pre-release/nightly.
2. **MaxMind MMDB provider:** полноценный путь к `.mmdb` и выбор провайдера (сейчас заглушка `maxmind.go`).
3. **CrowdSec в UI:** unblock / ban / delete decision через LAPI (см. также §7.5).
4. **Prometheus:** экспорт метрик на `/metrics` (рядом с существующим API stats).
5. **Diagnostics bundle:** скрипт `scripts/diagnostics.sh` (логи, версии, конфиг-снимок, проверки сокетов) для поддержки.
6. **OVA/OVF appliance template** для быстрого развёртывания ВМ.
7. **Smoke test checklist** (ручной/полуавтоматический прогон после установки).
8. **Тесты:** расширенные e2e / дерево `tests/` против compose PostgreSQL.
9. **UI:** при желании отдельный фронтенд-фреймворк вместо одного `index.html`.

Обновляй этот файл при закрытии пунктов MVP и при смене `VERSION`.

## Golden tests: **Done**

Фикстуры `Render()` → снимки `internal/haproxy/testdata/golden/<scenario>.cfg` + `<scenario>.crt-list.txt`; обновление: `make golden-update` (`UPDATE_GOLDEN=1`). Юнит-тест: `go test ./internal/haproxy/... -run Golden`. Интеграция `haproxy -c` по golden-файлам: `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (см. `render_golden_integration_test.go`).

## CI (GitHub Actions)

| Требование | Статус | Где |
|------------|--------|-----|
| `go vet`, golangci-lint, `go test -run Golden` (HAProxy golden), `go test -race` (с `-skip TestGoldenRender`, чтобы не дублировать golden), проверка артефактов Linux / LF в `scripts/**/*.sh`, `haproxy -c` на сгенерированном конфиге + golden (`-tags=integration`) | **Done** | `.github/workflows/ci.yml`, `internal/haproxy/render_golden_test.go`, `internal/haproxy/haproxy_validate_test.go` |
