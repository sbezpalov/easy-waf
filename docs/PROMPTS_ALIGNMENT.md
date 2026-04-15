# Соответствие `prompts.md` (Easy Home WAF)

Этот документ **привязывает** требования из [prompts.md](../prompts.md) к коду и докам репозитория. Статусы: **Done** | **Partial** | **Missing** | **N/A** (вне MVP / перенесено).

## §2 Goals — Core

| Требование | Статус | Где |
|------------|--------|-----|
| Публикация сервисов по доменам → backend | Partial | `internal/config/types.go`, `internal/haproxy/render.go`, API `applications` |
| TLS на HAProxy | Partial | crt-list, сертификаты из ACME / DB |
| ACME выдача/продление | Partial | `cmd/easy-waf-acmed`, `internal/acme/*`, `docs/ACME.md` |
| WebSocket | Partial | Поля приложения + шаблон HAProxy |
| Единая точка входа HAProxy | Partial | Рендер `haproxy.cfg` под edge |

## §2 Security

| Требование | Статус | Где |
|------------|--------|-----|
| Rate limit (stick-tables) | Partial | `internal/profiles/profiles.go` → шаблон |
| Базовый WACL (ACL) | Partial | Профили, `internal/haproxy/render.go` |
| CrowdSec + решения | Partial | `internal/crowdsec/client.go`, API `integrations/crowdsec*`, `docs/CROWDSEC.md` |
| SPOE bouncer | Partial | Настройки SPOE path / engine; полная автосборка в `install.sh` — нет (см. interactive) |
| Fail2Ban | Partial | Установка в `install.sh`, не оркестрируется API |
| GeoIP + кэш | Done | `internal/geoip/*` (LRU+TTL, ipinfo.io, batch `geoip_enforce.map`), API `/geoip/lookup`, `/geoip/stats`, HAProxy ACL, UI Settings |

## §2 UX / Observability

| Требование | Статус | Где |
|------------|--------|-----|
| Web UI (LAN) | Partial | `internal/webui/dist/index.html` (минимальный SPA) |
| Сертификаты, логи, статы, health | Partial | API + HAProxy stats socket (`internal/metrics`), `/stats/haproxy`, `/stats/summary`, Dashboard traffic/backends |
| Backup/restore | Done | `scripts/backup.sh`, `restore.sh`, `scripts/test-backup-restore.sh`, `docs/BACKUP_RESTORE.md` |

## §3 Constraints

| Требование | Статус | Где |
|------------|--------|-----|
| Alma 10, systemd, firewalld, SELinux | Done | `scripts/install.sh`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md` |
| `haproxy -c` до reload | Done | `internal/apply/apply.go`, `internal/engine/engine.go` |
| SPOE, WebSocket, SNI, redirect | Partial | Шаблон HAProxy; проверять под конкретный релиз |
| CrowdSec LAPI не Lua | Partial | Доки + SPOA пакет через interactive |
| Генератор, валидация, атомарный apply, rollback | Partial | apply + revisions в engine |
| GeoIP API + кэш + смена на MMDB | Partial | ipinfo + batch map — **Done**; MaxMind MMDB — заглушка (`maxmind.go`) |

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

### 7.1 App publishing — **Partial** (модель + API + рендер; health/path префиксы — по месту)

### 7.2 ACME — **Partial** (HTTP-01, DNS-01 задел, renew worker, apply hook)

### 7.2a Global settings API — **Done** (`GET /api/v1/settings`; **`PATCH /api/v1/settings`** — частичный JSON, merge поверх текущих значений в памяти/DB; **`PUT /api/v1/settings`** — тот же merge, чтобы частичное тело не обнуляло пути/таймауты; поля `geoip_cache_ttl` и `acme_renewal_interval` в JSON как строки `time.ParseDuration`, например `"24h"`, `"30m"`, плюс приём числа наносекунд для старых снимков; UI сохраняет ACME через PATCH) — `internal/api/server.go`, `internal/config/settings_merge.go`, `internal/config/duration.go`, `internal/webui/dist/index.html`

### 7.3 HAProxy engine — **Partial** (шаблон, checksum, validate, revisions/rollback в engine)

### 7.4 Security profiles — **Done** (имена из prompts: `balanced`, `strict`, `trusted-lan`, `public-app`, `home-assistant`) — `internal/profiles/profiles.go`, `docs/SECURITY_PROFILES.md`

### 7.5 CrowdSec — **Partial** (ping LAPI, `GET /api/v1/integrations/crowdsec/decisions`; whitelist/unblock в UI — не реализовано, использовать `cscli` / LAPI)

### 7.6 GeoIP — **Done** (`internal/geoip`, `GET /api/v1/geoip/lookup`, `GET /api/v1/geoip/stats`, настройки `geoip_*`, миграция `007`, batch `geoip_enforce.map` + ACL в `render.go`, секция в UI)

### 7.7 UI страницы — **Partial** (`internal/webui/dist/index.html`: вход, смена пароля, приложения, apply, сертификаты, CrowdSec ping/decisions, settings incl. GeoIP + ACME)

### 7.8 Statistics — **Done** (`internal/metrics` — HAProxy `show stat` over Unix socket, cache 5s; API `GET /api/v1/stats/haproxy`, `GET /api/v1/stats/summary`; Dashboard traffic + backends, refresh 10s; `haproxy_stats_socket_path` + golden template)

## §8 Lessons learned

Зафиксировано в `docs/ARCHITECTURE.md`, `docs/CROWDSEC.md`, `internal/haproxy/render.go` (SNI, ws, валидация).

## §9 Acceptance criteria (MVP)

| Критерий | Статус |
|----------|--------|
| install.sh | Done |
| Приложение через UI | Partial (минимальный UI) |
| HTTPS cert автоматически | Partial (нужны DNS/HTTP-01 и настройки) |
| Доступ снаружи к приложению | Зависит от HAProxy + NAT |
| CrowdSec блокирует, 403 | После установки SPOA + сценариев |
| Apply без даунтайма / rollback | Partial |
| UI: apps, certs, blocked | Partial (API богаче веба) |
| Reboot, SELinux | Целевой сценарий — Done при соблюдении доков |

## Roadmap (следующие итерации)

1. **Метрики**: stats socket HAProxy + агрегация в API (`internal/metrics`).
2. **UI**: отдельные маршруты/страницы или фреймворк; логи/аудит из `audit_log`.
3. **CrowdSec**: кнопка «обновить decisions», опционально delete decision через LAPI.
4. **GeoIP**: MaxMind MMDB / live lookup path при необходимости.
5. **Тесты**: интеграционные `tests/` против podman-compose PostgreSQL.

Обновляй этот файл при закрытии пунктов MVP.

## Golden tests: **Done**

Фикстуры `Render()` → снимки `internal/haproxy/testdata/golden/<scenario>.cfg` + `<scenario>.crt-list.txt`; обновление: `make golden-update` (`UPDATE_GOLDEN=1`). Юнит-тест: `go test ./internal/haproxy/... -run Golden`. Интеграция `haproxy -c` по golden-файлам: `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (см. `render_golden_integration_test.go`).

## CI (GitHub Actions)

| Требование | Статус | Где |
|------------|--------|-----|
| `go vet`, golangci-lint, `go test -run Golden` (HAProxy golden), `go test -race` (с `-skip TestGoldenRender`, чтобы не дублировать golden), проверка артефактов Linux / LF в `scripts/**/*.sh`, `haproxy -c` на сгенерированном конфиге + golden (`-tags=integration`) | **Done** | `.github/workflows/ci.yml`, `internal/haproxy/render_golden_test.go`, `internal/haproxy/haproxy_validate_test.go` |
