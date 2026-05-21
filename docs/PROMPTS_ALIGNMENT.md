# Соответствие `prompts.md` (Easy Home WAF)

**Последнее обновление:** 2026-04-20  
**Текущий VERSION:** 1.0.0 (см. корневой файл `VERSION`)  
**Сводка по строкам таблиц §2–§3:** Done — **20**, Partial — **1**, Missing — **0**, N/A — **0**

Этот документ **привязывает** требования из [prompts.md](../prompts.md) к коду и докам репозитория. Статусы: **Done** | **Partial** | **Missing** | **N/A** (вне MVP / перенесено).

Источник истины по реализации — **§7 Features** и проверка приёмки — **§9 Acceptance criteria**. Ниже в §2–§3 только компактный указатель со статусом и ссылкой `см. §7.*` / при необходимости на §9.

## Security hardening (audit follow-up)

| Item | Status | Where |
|------|--------|-------|
| **CSRF** | **Done** | JWT Bearer in `Authorization` (not cookies) + **`X-Requested-With: XMLHttpRequest`** on POST/PUT/PATCH/DELETE via `internal/api/csrf.go` (`RequireXHR`), UI `hdr()` in `internal/webui/dist/index.html`, docs `docs/ARCHITECTURE.md` / `docs/SECURITY.md`; curl scripts set the header (`scripts/restore.sh`, `scripts/test-backup-restore.sh`, `scripts/update-geoip-db.sh`) |
| **Login rate limit** | **Done** | Per-IP sliding window **10 attempts / 5 min**, lockout **15 min**; `internal/api/ratelimit.go`, `handleLogin` in `internal/api/auth_handlers.go`, `LoginRL` wired in `internal/bootstrap/run.go` |
| **Hostname validation** | **Done** | `validateAppHostnames` on `POST /api/v1/applications` — `internal/api/validate_application.go` |
| **Mgmt ACL XFF spoofing** | **Done** | `TrustedRealIP` — forwarding headers trusted only from `EASY_WAF_TRUSTED_PROXY_CIDRS` (default loopback); `internal/api/realip.go` |
| **Host diag injection** | **Done** | `internal/host/diag` — host validation on Ping/Trace; `ping`/`traceroute`/`tracepath` use `--` before target; tests reject `-T`, `--port=22`, `; rm` |
| **IPBL SSRF guard** | **Done** | `internal/ipbl/ssrfguard.go` — hard floor (loopback/metadata/link-local/CGNAT always blocked) + granular `ipbl_fetch_allowed_cidrs` for RFC1918 feeds; dial-time anti–DNS rebinding; `POST /ipbl/sources` validates URL |
| **Split-DNS resilience** | **Done** | IPBL trusted CIDRs UI + `ipbl_fetch_allowed_cidrs`; HAProxy `resolvers easy_waf_dns` + `init-addr` for FQDN backends (`internal/haproxy/render.go`); `acme_dns_resolvers` for Lego DNS-01 propagation; [DNS.md](DNS.md) |
| **Host systemd whitelist** | **Done** | `AllowedUnit` / `AllowedAction` in `internal/host/systemd/allow.go` (parity with `privileged.sh`); `host_handlers` 400 before privileged call |
| **SSH authorized_keys** | **Done** | `internal/host/users/sshkeys.go` — OpenSSH line regex; reject embedded newlines; no file write on invalid key |
| **Journal allowlist** | **Done** | `internal/host/journal` — only `-n`, `-u`, `--since`, `--until`, `-p`, `--no-pager`; unit on systemd whitelist |
| **Host management in GUI** | **Done** (part 1) | **System** tab: services (allowlisted systemd), apt check/upgrade (**live NDJSON stream** via `POST /host/updates/upgrade/stream`), reboot/shutdown. **Network** tab: read-only overview; netplan + nftables **Advanced** apply with 90s safety window + **Keep changes** (commit); auto-revert via `systemd-run` → `easy-waf-hostd revert`. **Users** tab stub — part 2 (accounts, journal, ping/trace, form editors). |
| **Realtime apt-upgrade log (NDJSON stream)** | **Done** | `apt-upgrade-stream` in `easy-waf-hostd`; API passthrough + System UI `fetch` stream |
| **System → Updates: autoremove (preview + live stream)** | **Done** | `apt-autoremove-simulate` / `apt-autoremove-stream`; shared apt single-flight; UI preview → confirm → `runAptStream` |
| **Host privilege model** | **Done** | Root broker **`easy-waf-hostd`** on `/run/easy-waf/hostd.sock`; `runner.Privileged` uses JSON over unix socket; API keeps `NoNewPrivileges`/`ProtectSystem=strict`; legacy sudo + `host-privileged.sh` removed on install |

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
| CrowdSec + решения (LAPI, decisions в UI) | **Done** | см. **§7.5** (ban/unban/whitelist в UI) |
| SPOE bouncer | **Done** | см. **§7.3**; шаблон `filter spoe` / `send-spoe-group`; `install.sh`, `docs/CROWDSEC.md` |
| Fail2Ban | **Done** | `GET/POST /api/v1/integrations/fail2ban/*` via **`easy-waf-hostd`** (`fail2ban` opcode); UI вкладка Fail2Ban; `docs/FAIL2BAN.md`; legacy socket/group path retired |
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
| Ubuntu 24.04 LTS, systemd, nftables, AppArmor | **Done** | `scripts/install.sh`, `docs/DEPLOYMENT.md`, `docs/SECURITY.md`, `docs/HOST-API.md` |
| `haproxy -c` до reload | **Done** | см. **§7.3**; `internal/apply`, `internal/engine` |
| SPOE, WebSocket, SNI, redirect (golden + CI) | **Done** | см. **§7.3** |
| CrowdSec LAPI не через Lua | **Done** | Go LAPI client + SPOA пакет; см. **§7.5**, `docs/CROWDSEC.md` |
| Генератор конфига, валидация, атомарный apply, rollback | **Done** | см. **§7.3**; **§9** AC-06 |
| GeoIP API + batch map + ACL | **Done** | см. **§7.6** |
| MaxMind MMDB как провайдер | **Done** | `geoip_mmdb_path`, `internal/geoip/maxmind.go`, `GET/POST /api/v1/geoip/*`, `docs/GEOIP.md`, `scripts/update-geoip-db.sh` |

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

### 7.1 App publishing — **Done** (CRUD API + UI, профили, restricted paths, health path в модели; **HTTP publishing**: per-app `listen_mode`, `fe_http` маршрутизация / per-host redirect, миграция `012_listen_mode.sql`, golden `http-only-app` / `mixed-listen-modes` / `http-only-reverse-proxy`, audit `app_listen_mode_changed`)

### 7.1a Per-application security — **Done** (миграция `009_application_security.sql`, `Application.security`, пресеты `internal/profiles/modes.go`, HAProxy per-host ACL порядок, per-app GeoIP maps `geoip_app_*.map`, API `GET/PUT/PATCH /applications/{id}/security`, `POST …/security/mode`, `GET /security/modes`, audit `app_security_mode_changed`, UI карточки + Dashboard overview, golden `app-*` / `mixed-apps`, `docs/APPLICATION_SECURITY.md`)

### 7.2 ACME — **Done** (HTTP-01, DNS-01 провайдеры, renew worker, apply hook в `easy-waf-acmed`)

### 7.2a Global settings API — **Done** (`GET /api/v1/settings`; **`PATCH /api/v1/settings`** — частичный JSON, merge поверх текущих значений в памяти/DB; **`PUT /api/v1/settings`** — тот же merge, чтобы частичное тело не обнуляло пути/таймауты; поля `geoip_cache_ttl` и `acme_renewal_interval` в JSON как строки `time.ParseDuration`, например `"24h"`, `"30m"`, плюс приём числа наносекунд для старых снимков; UI сохраняет ACME через PATCH) — `internal/api/server.go`, `internal/config/settings_merge.go`, `internal/config/duration.go`, `internal/webui/dist/index.html`

### 7.3 HAProxy engine — **Done** (шаблон, checksum, validate, revisions/rollback, golden)

### 7.4 Security profiles — **Done** (имена из prompts: `balanced`, `strict`, `trusted-lan`, `public-app`, `home-assistant`) — `internal/profiles/profiles.go`, `docs/SECURITY_PROFILES.md`

### 7.5 CrowdSec — **Done** (ping LAPI, decisions в UI, **Unban** / **Ban IP** / **Allow IP (whitelist)** через LAPI; операции `cscli` вне UI — по докам)

### 7.6 GeoIP — **Done** (`internal/geoip` — ipinfo + **MaxMind GeoLite2-Country.mmdb**, `GET /api/v1/geoip/lookup|stats|providers`, `POST /api/v1/geoip/reload`, настройки `geoip_*` / `geoip_mmdb_path`, миграции `007`+`010`, batch `geoip_enforce.map` + ACL в `render.go`, секция в UI, `docs/GEOIP.md`)

### 7.7 UI страницы — **Done** (вкладки из §7 prompts + audit/logs, certificate summary)

### 7.8 Statistics — **Done** (`internal/metrics` — HAProxy `show stat` over Unix socket, cache 5s; API `GET /api/v1/stats/haproxy`, `GET /api/v1/stats/summary`; Dashboard traffic + backends, refresh 10s; `haproxy_stats_socket_path` + golden template)

## §8 Lessons learned

Зафиксировано в `docs/ARCHITECTURE.md`, `docs/CROWDSEC.md`, `internal/haproxy/render.go` (SNI, ws, валидация).

## §9 Acceptance criteria (MVP) — ТЗ v1.1 (AC-01 … AC-10)

Проверка по коду и скриптам (итерации A–D). **Partial** = поведение зависит от среды (NAT, DNS, пакет SPOA) или осознанно вынесено из UI.

| ID | Критерий | Статус | Проверка в репозитории |
|----|----------|--------|-------------------------|
| **AC-01** | Установка через `install.sh` на Ubuntu 24.04 LTS (полный цикл: пакеты, layout, env, PostgreSQL опционально, бинарники, systemd) | **Done** | `scripts/install.sh` — `apt`, nftables, CrowdSec+SPOA packages, **LAPI bootstrap** (bouncers, `CROWDSEC_LAPI_*`, `-sync-settings-only`), `create_user_and_layout`, `install_env_file`, `systemctl enable --now easy-waf-api.service easy-waf-acmed.service` (флаг `EASY_WAF_ENABLE_SYSTEMD_UNITS`), юниты `packaging/systemd/*.service`, `WantedBy=multi-user.target` |
| **AC-02** | Добавление app через UI + Apply | **Done** | UI `#apps` → `POST /api/v1/applications`; `#config` → `POST /api/v1/apply`; `internal/api/server.go`, `internal/engine/engine.go` |
| **AC-03** | HTTPS-сертификат автоматически (ACME) | **Partial** | `cmd/easy-waf-acmed` — выдача/renew, после успеха `eng.Apply(ctx,"acme")`; нужны `ACME_EMAIL`, DNS/HTTP-01, worker запущен (`docs/ACME.md`) |
| **AC-04** | Доступ извне к опубликованному приложению | **Partial** | Рендер `fe_http`/`fe_https`, SNI, бэкенды по Host — **Done** в коде; маршрутизация WAN/NAT/port-forward — вне репозитория |
| **AC-05** | CrowdSec блокирует; HAProxy отдаёт 403 для запрещённого трафика | **Partial** | В шаблоне `filter spoe engine …` + ACL с `deny_status 403` (WAF, IPBL, GeoIP, UA); реакция на decision из SPOA — конфиг пакета bouncer + `docs/CROWDSEC.md` |
| **AC-06** | Apply + rollback | **Done** | `engine.Apply` / `Rollback`, ревизии в БД; `POST /revisions/{id}/rollback`; UI Config (таблица ревизий + кнопка) |
| **AC-07** | UI: apps, certs, blocked | **Done** | Вкладки Applications, Certificates (в т.ч. summary/actions), Security (IPBL, blocked UA), Dashboard |
| **AC-08** | Переживает reboot | **Done** | `systemctl enable` для api/acmed (и опционально CrowdSec); `Restart=on-failure` в unit-файлах |
| **AC-09** | WebSocket (например HA) | **Done** | `timeout tunnel` в defaults и для `websocket` в `internal/haproxy/render.go` |
| **AC-10** | Backup + restore | **Done** | `scripts/backup.sh`, `scripts/restore.sh`, `docs/BACKUP_RESTORE.md`, `scripts/test-backup-restore.sh` |

**AppArmor (из §3 prompts):** Ubuntu использует AppArmor по умолчанию; отдельный профиль easy-waf не требуется. Доступ HAProxy к конфигам — через группу **`easy-waf`**. Статус: **Done** на Ubuntu 24.04.

## Roadmap (после MVP)

1. **Release pipeline (базово сделано):** [`.github/workflows/release.yml`](../.github/workflows/release.yml) — push тега `v*`, `make build`, tarball + `SHA256SUMS`, GitHub Release с текстом из `CHANGELOG.md`. Далее: подпись артефактов, pre-release/nightly.
2. **MaxMind MMDB (done):** см. **`docs/GEOIP.md`**, **`scripts/update-geoip-db.sh`**. Далее: подпись MMDB, метрики размера/epoch файла.
3. ~~**CrowdSec в UI**~~ — done (ban/unban/whitelist).
4. ~~**Prometheus `/metrics`**~~ — done (`docs/MONITORING.md`).
5. ~~**Diagnostics bundle**~~ — done (`scripts/diagnostics.sh`, API bundle, `docs/DIAGNOSTICS.md`).
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
