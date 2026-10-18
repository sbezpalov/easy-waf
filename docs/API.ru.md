# Справочник REST API
[English](API.md) | **Русский** · канонический документ — английский; при расхождении верна английская версия. Переведено с 1.4.2.

Управляющий API `easy-waf-api` — тот же API, которым пользуется встроенный веб-интерфейс.
Все маршруты регистрируются в [`internal/api/server.go`](../internal/api/server.go),
а для `/api/v1/host/*` — в [`internal/api/host_handlers.go`](../internal/api/host_handlers.go).
Если эта страница расходится с кодом, прав код — пожалуйста, исправьте страницу.

## Содержание

- [Основы](#основы)
- [Аутентификация](#аутентификация)
- [Статус и каталог](#статус-и-каталог)
- [Приложения](#приложения)
- [Безопасность приложений](#безопасность-приложений)
- [Apply и ревизии](#apply-и-ревизии)
- [Сертификаты](#сертификаты)
- [Настройки](#настройки)
- [Статистика](#статистика)
- [Журнал аудита](#журнал-аудита)
- [Диагностика](#диагностика)
- [Блоклист IP (IPBL)](#блоклист-ip-ipbl)
- [Allowlist IP](#allowlist-ip)
- [Блокируемые User-Agent](#блокируемые-user-agent)
- [GeoIP](#geoip)
- [CrowdSec](#crowdsec)
- [Fail2Ban](#fail2ban)
- [Health-пробы и метрики](#health-пробы-и-метрики)
- [Управление хостом](#управление-хостом)

## Основы

**Базовый URL.** API обслуживается управляющими листенерами, а не edge-слоем
HAProxy:

- HTTPS на **`EASY_WAF_LISTEN_HTTPS`** (по умолчанию `0.0.0.0:8443`);
- HTTP в открытом виде на **`EASY_WAF_LISTEN_HTTP`** — только если вы его включили (по умолчанию выключен;
  только loopback, если не задано `EASY_WAF_ALLOW_INSECURE_HTTP=1`).

Пути ниже указаны относительно этого origin, например `https://<appliance>:8443/api/v1/status`.
Тела запросов и ответов — JSON, если не сказано иное.

**Каждый запрос проходит по порядку:** заголовки безопасности → ограничение тела
запроса в 4 MiB → определение IP клиента с учётом доверенных прокси → ACL по
адресу источника для управляющей плоскости → проверку `X-Requested-With` → для
`/api/v1` (кроме трёх публичных маршрутов аутентификации) аутентификацию сессии,
аудит изменяющих вызовов и барьер обязательной смены пароля.

### ACL управляющей плоскости

Запросы принимаются только с адресов из глобальной настройки
`management_allowed_cidrs` (по умолчанию: loopback, `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`). Остальные получают **403**
`{"error":"management access denied for this source address"}`.
`/health` и `/health/ready` из-под ACL исключены; `/metrics` — нет.

Адрес клиента — это TCP-пир. Только если пир входит в
`EASY_WAF_TRUSTED_PROXY_CIDRS`, вместо него берётся самое правое значение
`X-Forwarded-For`, поэтому прокси обязан перезаписывать этот заголовок, а не дописывать в него.
Аварийный обход: `EASY_WAF_BYPASS_MGMT_ACL=1` (см. [ADMIN-CLI.md](ADMIN-CLI.md#environment-bypass-lockout)).

### `X-Requested-With` (защита от CSRF)

Каждый `POST`, `PUT`, `PATCH` и `DELETE` обязан передавать
`X-Requested-With: XMLHttpRequest`; иначе — **403**
`{"error":"missing X-Requested-With header"}`. Для `GET`, `HEAD` и `OPTIONS` он
не нужен. См. [SECURITY.ru.md](SECURITY.ru.md#защита-от-csrf).

### Вход и сессии

1. **Первый запуск:** пока учётной записи оператора нет, `GET /api/v1/auth/status` сообщает,
   что требуется регистрация. Выведите одноразовый секрет на appliance командой
   `sudo easy-waf-admin print-enrollment` и создайте учётную запись через
   `POST /api/v1/auth/enroll`. Учётной записи `admin/admin` по умолчанию нет.
2. **Вход:** `POST /api/v1/auth/login` возвращает
   `{"token": "...", "must_change_password": false, "expires_in_seconds": 86400}`.
3. **Вызывайте API** с заголовком `Authorization: Bearer <token>`. Токены — это JWT с HS256,
   действительные **24 часа**; в cookie они никогда не устанавливаются.
4. **Выход** — `POST /api/v1/auth/logout`: он увеличивает версию сессии учётной
   записи, что отзывает *все* токены, выданные этой учётной записи, а не только
   использованный.

Отсутствующий, недействительный, просроченный или отозванный токен получает **401** `{"error":"unauthorized"}`.

**Барьер смены пароля.** Пока учётная запись ещё обязана сменить начальный
пароль, все аутентифицированные маршруты, кроме `GET /api/v1/auth/me` и
`POST /api/v1/auth/change-password`, возвращают **403**
`{"error":"password_change_required","must_change_password":true}`.

**Токен автоматизации.** Если задан `EASY_WAF_ADMIN_TOKEN` (не короче 24
символов), это значение тоже принимается как bearer-токен. Он действует от имени
принципала `automation`, не подпадает под барьер смены пароля и не отзывается
выходом — ротируйте его, изменив окружение и перезапустив API. Для любой
интерактивной работы предпочитайте сессионный токен.

**Ограничение частоты входа.** `POST /auth/login`, `POST /auth/enroll` и
`POST /auth/change-password` делят общий лимит на IP: 10-я попытка за
5 минут запускает блокировку на **15 минут**, в течение которой они возвращают **429**
с `Retry-After: <seconds>`. Успешная попытка сбрасывает счётчик для этого
адреса.

### Ошибки

Ошибки сообщаются HTTP-кодом статуса. Тело ответа **не единообразно**:

- описанные выше middleware и многие обработчики возвращают JSON `{"error": "<message>"}`;
- другие обработчики возвращают сообщение как **`text/plain`** (`http.Error` из Go).

Опирайтесь на код статуса, а тело считайте сообщением для человека. В разделах
эндпоинтов указано, какую форму использует обработчик, там, где это важно.

Типичные статусы: **400** — некорректный JSON или непройденная валидация, **401** — нет действительной
сессии, **403** — ACL / `X-Requested-With` / барьер смены пароля, **404** —
неизвестный id, **413** — тело больше 4 MiB, **422** — HAProxy отверг изменение (оно
отменено), **429** — блокировка входа, **500** — ошибка базы данных или внутренняя ошибка,
**502/503** — недоступен вышестоящий компонент (CrowdSec LAPI, брокер хоста, PostgreSQL).

### Аудит

Каждый `POST`, `PUT`, `PATCH` и `DELETE` под `/api/v1`, прошедший
аутентификацию, записывается в журнал аудита как `"<METHOD> <path>"` с его
HTTP-статусом, укрупнённой категорией, пользователем и адресом источника — независимо от того,
успешен он или нет. Тела запросов никогда не сохраняются. Некоторые обработчики также записывают
более конкретное действие. Журнал читается через [`GET /api/v1/audit`](#get-apiv1audit).

### Заголовки ответа

Все ответы содержат `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, строгие
`Content-Security-Policy` и `Permissions-Policy`; ответы по HTTPS дополнительно содержат
`Strict-Transport-Security: max-age=31536000; includeSubDomains`.

### Пример

```bash
BASE=https://192.0.2.10:8443
TOKEN=$(curl -sk "$BASE/api/v1/auth/login" \
  -H 'Content-Type: application/json' -H 'X-Requested-With: XMLHttpRequest' \
  -d '{"username":"operator","password":"…"}' | jq -r .token)

curl -sk "$BASE/api/v1/applications" -H "Authorization: Bearer $TOKEN"

curl -sk -X POST "$BASE/api/v1/apply" \
  -H "Authorization: Bearer $TOKEN" -H 'X-Requested-With: XMLHttpRequest'
```

`-k` нужен только для самоподписанного управляющего сертификата свежего appliance;
перейдите на `--cacert`, как только установите собственный (`PUT /api/v1/settings/management-tls`).

## Аутентификация

`status`, `login` и `enroll` не требуют сессии. `login`, `enroll` и `change-password` делят один лимитер на IP (`LoginRateLimiter`, настроен в `internal/bootstrap/run.go`: 10 попыток в скользящем окне 5 минут, затем блокировка на 15 минут). Каждый запрос, прошедший лимитер, считается попыткой — успешен он или нет. 10-я попытка в окне ещё обрабатывается, но запускает блокировку. Пока действует блокировка, запросы отклоняются и не засчитываются. Успешный вход, регистрация или смена пароля обнуляет счётчик для этого IP. Если IP клиента определить нельзя, лимит не применяется. Эти три обработчика сами ограничивают тело запроса 16 KiB (`maxLoginRequestBodyBytes`).

### `GET /api/v1/auth/status`
Сообщает, ждёт ли appliance ещё регистрации первого оператора. Без аутентификации, только чтение.
- **Ответ:** `200`
  ```json
  {"enrollment_required": true, "enrollment_file": "/var/lib/easy-waf/secrets/enrollment"}
  ```
  `enrollment_required` равно true, когда нет ни одного оператора и секрет регистрации ещё не использован. `enrollment_file` — итоговый путь к секрету регистрации, `<state_dir>/secrets/enrollment`.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/auth/login`
Проверяет имя пользователя и пароль локального оператора и выдаёт сессионный JWT, действительный 24 часа (`sessionTTL`). Неудачи записывают строку аудита `login_failed`, а запросы, упёршиеся в лимит, — `login_rate_limited`.
- **Тело запроса:**
  - `username` (string, обязательно; пробелы по краям обрезаются; не более 128 байт)
  - `password` (string, обязательно; не более 256 байт)
  ```json
  {"username": "admin", "password": "correct horse battery"}
  ```
- **Ответ:** `200`
  ```json
  {"token": "<jwt>", "must_change_password": false, "expires_in_seconds": 86400}
  ```
  Если `must_change_password` равно true, до смены пароля сессии доступны только `/auth/me`, `/auth/logout` и `/auth/change-password`.
- **Ошибки:**
  - `400` (text/plain): некорректный JSON, отсутствует имя пользователя или пароль либо учётные данные превышают лимиты длины.
  - `401` (JSON): `{"error": "invalid credentials"}` для неизвестного пользователя или неверного пароля. Если пользователь неизвестен, а регистрация ещё не завершена, тело вместо этого — `{"error": "enrollment required"}`.
  - `429` (JSON) с заголовком `Retry-After` в секундах: `{"error": "too many login attempts, try again later"}`.
  - `500` (text/plain): не удалось подписать токен.

### `POST /api/v1/auth/enroll`
Создаёт первого оператора по одноразовому секрету регистрации, удаляет файл регистрации и возвращает сессию так же, как вход. Записывает действия аудита `enrollment_completed`, `enrollment_failed` или `enrollment_rate_limited`.
- **Тело запроса:**
  - `secret` (string, обязательно; пробелы обрезаются; не более 256 байт): содержимое `<state_dir>/secrets/enrollment`.
  - `username` (string, необязательно; по умолчанию `admin`; не более 128 байт).
  - `password` (string, обязательно; не менее 8 символов после обрезки пробелов; не более 72 байт — предел входа bcrypt).
  ```json
  {"secret": "<64 hex chars>", "username": "admin", "password": "a-long-passphrase"}
  ```
- **Ответ:** `200`, той же формы, что и при входе. `must_change_password` всегда `false`.
- **Ошибки:**
  - `400` (text/plain): некорректный JSON, отсутствует секрет или пароль, слишком длинные значения (`credentials are too long`), пароль короче 8 символов или пароль длиннее 72 байт (`password must be at most 72 bytes`).
  - `401` (JSON): `{"error": "invalid enrollment secret"}`. Возвращается при неверном секрете, а также когда записи о регистрации нет.
  - `409` (JSON): `{"error": "enrollment already completed"}`. Оператор уже существует или секрет уже использован.
  - `429` (JSON) с `Retry-After`: `{"error": "too many enrollment attempts, try again later"}`.
  - `500` (text/plain): ошибка хеширования, базы данных или токена.

### `GET /api/v1/auth/me`
Возвращает данные вызывающего. Работает, пока смена пароля ещё не выполнена.
- **Ответ:** `200` `{"username": "admin", "must_change_password": false}`. С устаревшим `EASY_WAF_ADMIN_TOKEN` ответ всегда `{"username": "automation", "must_change_password": false}`.
- **Ошибки:** `404` (text/plain), если строки пользователя больше нет.

### `POST /api/v1/auth/logout`
Завершает сессию вызывающего на стороне сервера, увеличивая `session_version` пользователя. Это отзывает все JWT, выданные этому пользователю, на всех устройствах, а не только текущий. Тела запроса нет. Запрос порождает две строки аудита: собственную строку обработчика `logout` и общую строку изменения `"POST /api/v1/auth/logout"`.
- **Ответ:** `200` `{"revoked": true}`
- **Ошибки:** `400` (text/plain) при вызове с устаревшим токеном автоматизации, у которого нет сессии для отзыва. `404` (text/plain), если пользователь не найден. `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/auth/change-password`
Меняет пароль вызывающего, сбрасывает `must_change_password`, отзывает все существующие сессии (увеличивая `session_version`) и возвращает новый токен. Работает, пока смена пароля ещё не выполнена. Подпадает под общий лимитер на IP; успешная смена обнуляет счётчик для IP вызывающего. Запрос порождает две строки аудита: `password_changed` и общую строку изменения `"POST /api/v1/auth/change-password"`.
- **Тело запроса:**
  - `current_password` (string, обязательно)
  - `new_password` (string, обязательно; не менее 8 символов после обрезки пробелов; не более 72 байт)
  ```json
  {"current_password": "old-secret", "new_password": "a-new-long-passphrase"}
  ```
- **Ответ:** `200`, той же формы, что и при входе, с `must_change_password: false`. Токен, использованный для этого вызова, перестаёт работать, поэтому клиент должен перейти на возвращённый.
- **Ошибки:**
  - `400` (text/plain): устаревший токен (`use local user session to change password`), некорректный JSON, новый пароль короче 8 символов или длиннее 72 байт (`password must be at most 72 bytes`).
  - `401` (text/plain): `current password incorrect`.
  - `404` (text/plain): пользователь не найден.
  - `429` (JSON) с `Retry-After`: `{"error": "too many attempts, try again later"}`.
  - `500` (text/plain): ошибка хеширования или базы данных либо `password changed but session could not be issued`, когда пароль сменён, но пользователя не удалось перечитать, чтобы подписать новый токен.

## Статус и каталог

### `GET /api/v1/status`
Минимальный статус управляющей плоскости.
- **Ответ:** `200` `{"state_dir": "/var/lib/easy-waf", "version": "1.4.0"}`. `version` берётся из переменной окружения `EASY_WAF_VERSION` и равен пустой строке, если переменная не задана.

### `GET /api/v1/system/services`
Сообщает systemd-состояние `ActiveState` основных юнитов appliance. Юниты опрашиваются по очереди (`systemctl show -p ActiveState --value`, с откатом на `systemctl is-active`) с таймаутом 5 секунд на юнит, покрывающим все попытки для этого юнита. При восьми юнитах зависший systemd может задержать ответ примерно до 40 секунд.
- **Ответ:** `200`
  ```json
  {"services": [
    {"id": "easy_waf_api", "unit": "easy-waf-api.service", "label": "Control plane + UI", "active_state": "active"}
  ]}
  ```
  Фиксированный список ID: `easy_waf_api`, `easy_waf_acmed`, `haproxy`, `crowdsec`, `crowdsec_spoa`, `nftables`, `fail2ban` и `postgresql`. `active_state` — то, что сообщает systemd (`active`, `inactive`, `failed`, `activating` и т. д.), либо `unknown`, если systemctl недоступен.
- **Ошибки:** нет. Сбои отображаются как `unknown`.

### `GET /api/v1/profiles`
Возвращает встроенный каталог профилей (`profiles.All()` в `internal/profiles/profiles.go`) в виде объекта с ключами по имени профиля: `balanced`, `strict`, `trusted-lan`, `public-app`, `home-assistant`, `none` и `custom`.
- **Ответ:** `200`. У каждого значения есть поля `name`, `description`, `rate_limit_rps`, `rate_limit_burst`, `connect_timeout_ms`, `server_timeout_ms` (целые числа, миллисекунды), `http_keep_alive`, `block_paths` и `extra_blocked_methods` (массивы, `[]`, если пусто), `geo_default_deny` и `notes` (опускается, если пусто).
  ```json
  {"balanced": {"name": "balanced", "description": "Reasonable defaults for most home apps",
    "rate_limit_rps": 50, "rate_limit_burst": 100, "connect_timeout_ms": 5000, "server_timeout_ms": 50000,
    "http_keep_alive": true, "block_paths": ["/.git", "..."], "extra_blocked_methods": ["TRACE", "CONNECT"],
    "geo_default_deny": false}}
  ```

### `GET /api/v1/security/modes`
Возвращает каталог пресетов режимов безопасности (`profiles.SecurityModeCatalog()` в `internal/profiles/mode_descriptions.go`).
- **Ответ:** `200`, массив объектов `{id, label, description, toggles, profile_hint?}`. ID по порядку: `full`, `balanced`, `trusted-lan`, `reverse-proxy-only` и `custom`. `toggles` сопоставляет ключам `rate_limit`, `path_acl`, `method_filter`, `basic_waf`, `bot_protection`, `ip_blacklist`, `ip_allowlist`, `geoip` и `crowdsec` булевы значения. Для `custom` объект `toggles` пуст. `profile_hint` — профиль, который пресет также устанавливает: `strict` для `full`, `balanced` для `balanced` и `trusted-lan` для `trusted-lan`. Для `reverse-proxy-only` и `custom` он отсутствует.

## Приложения

Приложение (`config.Application`, `internal/config/types.go`) сопоставляет публичное имя хоста с бэкендом. Его JSON-поля: `id`, `name`, `public_host`, `backend_host`, `backend_port`, `backend_https`, `backend_tls_verify`, `backend_tls_ca_file`, `backend_tls_server_name`, `websocket`, `health_path`, `path_prefix`, `restricted_paths` (`[{path_prefix, allowed_cidrs}]`), `profile`, `certificate_id`, `listen_mode`, `enabled`, `security` (см. [Безопасность приложений](#безопасность-приложений)), `created_at` и `updated_at`.

Изменяющие эндпоинты этого и следующего раздела сначала пишут в базу данных, а затем применяют изменение к HAProxy. Если apply не удался, изменение в базе отменяется и эндпоинт возвращает ошибку (text/plain) с сообщением вида `change not saved, edge apply failed: …`. Если не удалась и сама отмена, сообщение выглядит так: `edge apply failed: …; undoing the database change also failed, so it is saved but not live: …`. Код статуса:
- `503`, когда apply не уложился во время. Apply ждёт не более 2 минут, включая ожидание блокировки apply, поэтому обычно это значит, что ещё шёл другой apply; повтор может пройти успешно.
- `422` для любого другого сбоя apply (валидация, перезагрузка, …).

При `EASY_WAF_NO_AUTO_APPLY=1` шаг apply пропускается, и изменения вступают в силу только после `POST /api/v1/apply`.

### `GET /api/v1/applications`
Перечисляет все приложения, упорядоченные по `public_host`.
- **Ответ:** `200`, массив `config.Application`; `[]`, если приложений нет.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `GET /api/v1/applications/{id}`
Возвращает одно приложение.
- **Параметры пути:** `id` — ID приложения.
- **Ответ:** `200` `config.Application`.
- **Ошибки:** `404` (text/plain, `not found`) для неизвестного ID. `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/applications`
Создаёт или заменяет приложение (upsert), затем применяет его к HAProxy. Тело без `id` или с ещё не существующим `id` создаёт приложение; если `id` опущен, используется UUID, сгенерированный сервером. Тело с существующим `id` заменяет всю сохранённую строку целиком. Метка аудита для apply — `api-application`. Дополнительные строки аудита пишутся для:
- `app_listen_mode_changed` — когда у существующего приложения меняется `listen_mode`. Детали: `app_id`, `app_name`, `from` и `to`, плюс `severity: "warn"`, если любая из сторон — `http_only`.
- `backend_tls_verify_disabled` — когда у сохранённого приложения `backend_https: true` и `backend_tls_verify: "none"`.
- **Тело запроса:** `config.Application`. Обработка на сервере:
  - `profile` обязателен и должен быть одним из имён из `GET /profiles`.
  - `listen_mode` нормализуется к `https_only` (по умолчанию), `http_only`, `http_and_https` или `redirect_to_https`. Неизвестные значения превращаются в `https_only`.
  - `certificate_id` обязателен, если только `listen_mode` не равен `http_only`.
  - `id`, если указан, должен соответствовать `^[A-Za-z0-9][A-Za-z0-9_-]*$` и быть не длиннее 128 байт.
  - `public_host` — только строчные `a-z0-9.-`.
  - `backend_host` — только `A-Za-z0-9._:-`.
  - `backend_port` — от 1 до 65535.
  - `name` — не более 200 байт и без управляющих символов.
  - `health_path`, `path_prefix` и `restricted_paths[].path_prefix` должны проходить валидацию путей HAProxy. Каждый элемент `restricted_paths[].allowed_cidrs` должен быть IP-адресом или CIDR.
  - `backend_tls_verify` должен быть `required` (по умолчанию) или `none`. Если при обновлении он пуст, сохранённые `backend_tls_verify`, `backend_tls_ca_file` и `backend_tls_server_name` сохраняются.
  - `backend_tls_ca_file` должен быть абсолютным путём к файлу из allowlist.
  - `security`: переданные переключатели и прочие поля сохраняются, а `security.mode` игнорируется и вычисляется заново по девяти переключателям (`profiles.DetectMode`). Настройками `balanced` по умолчанию заменяется только блок, в котором ничего не задано (нет `mode`, все переключатели false, нет политики GeoIP или списка стран, нет переопределений rate limit), в том числе опущенный `security`. Чтобы сохранить все переключатели выключенными, укажите `mode` или используйте `POST /applications/{id}/security/mode` с `reverse-proxy-only`.
  - `created_at` и `updated_at` устанавливает сервер. При обновлении сохранённый `created_at` остаётся прежним и возвращается.
  ```json
  {
    "name": "Home Assistant",
    "public_host": "ha.example.com",
    "backend_host": "192.168.1.20",
    "backend_port": 8123,
    "backend_https": false,
    "websocket": true,
    "profile": "home-assistant",
    "certificate_id": "ha-example-com",
    "listen_mode": "redirect_to_https",
    "enabled": true,
    "security": {"mode": "balanced", "rate_limit_enabled": true, "path_acl_enabled": true,
                 "method_filter_enabled": true, "basic_waf_enabled": true, "bot_protection_enabled": true,
                 "ip_blacklist_enabled": true, "ip_allowlist_enabled": true, "geoip_enabled": false,
                 "crowdsec_enabled": true, "geoip_policy": "allow", "geoip_country_list": []}
  }
  ```
- **Ответ:** `200`, сохранённый `config.Application`, включая назначенный `id`. Если проверка TLS бэкенда отключена, возвращается тот же объект с дополнительным строковым полем `warning`.
- **Ошибки:**
  - `400` (text/plain): некорректный JSON, неизвестный профиль, отсутствует `certificate_id` или любой провал валидации из списка выше.
  - `422` / `503` (text/plain): apply не удался, и изменение отменено (см. выше). Для нового приложения отмена означает его повторное удаление.
  - `500` (text/plain): ошибка базы данных.

### `DELETE /api/v1/applications/{id}`
Удаляет приложение и применяет результат к HAProxy (метка аудита `api-application-delete`). Если apply не удался, удалённая строка возвращается на место.
- **Параметры пути:** `id`.
- **Ответ:** `204`, без тела.
- **Ошибки:** `404` (text/plain, `not found`) для неизвестного ID; ничего не применяется. `422` / `503` (text/plain), если apply не удался и строка восстановлена. `500` (text/plain) при ошибке базы данных.

## Безопасность приложений

У `config.ApplicationSecurity` (`internal/config/types.go`) такие поля:
- `mode`: одно из `full`, `balanced`, `trusted-lan`, `reverse-proxy-only` или `custom`.
- Переключатели (все булевы): `rate_limit_enabled`, `path_acl_enabled`, `method_filter_enabled`, `basic_waf_enabled`, `bot_protection_enabled`, `ip_blacklist_enabled`, `ip_allowlist_enabled`, `geoip_enabled` и `crowdsec_enabled`.
- `geoip_policy`: `allow` или `deny`. Любое значение, кроме `deny`, сохраняется как `allow`.
- `geoip_country_list`: массив кодов ISO 3166-1 alpha-2.
- `rate_limit_rps_override` и `rate_limit_burst_override`: необязательные целые числа.

При PUT и PATCH сервер заново вычисляет `mode` по девяти переключателям. Он становится именем пресета, переключатели которого совпадают в точности, или `custom`, если такого нет. Все три эндпоинта записи возвращают сохранённый `ApplicationSecurity` и применяют его к HAProxy — с отменой и поведением `422`/`503`, описанными в разделе [Приложения](#приложения). Для всех четырёх эндпоинтов неизвестное приложение — это `404` (text/plain, `not found`), а ошибка базы данных при его загрузке — `500`.

### `GET /api/v1/applications/{id}/security`
Возвращает объект `security` приложения.
- **Ответ:** `200` `config.ApplicationSecurity`.
- **Ошибки:** `404`, `500` (text/plain).

### `PUT /api/v1/applications/{id}/security`
Заменяет объект безопасности целиком, затем применяет (метка аудита `api-application-security`). Опущенные поля сбрасываются к нулевым значениям; `mode` вычисляется заново по переключателям. Настройками `balanced` по умолчанию заменяется только тело, в котором ничего не задано (см. правило для `security` в `POST /applications`).
- **Тело запроса:** `config.ApplicationSecurity`.
  ```json
  {"rate_limit_enabled": true, "path_acl_enabled": true, "method_filter_enabled": true,
   "basic_waf_enabled": true, "bot_protection_enabled": false, "ip_blacklist_enabled": true,
   "ip_allowlist_enabled": true, "geoip_enabled": true, "crowdsec_enabled": true,
   "geoip_policy": "deny", "geoip_country_list": ["CN", "RU"], "rate_limit_rps_override": 30}
  ```
- **Ответ:** `200`, сохранённый `config.ApplicationSecurity`. В этом примере `mode` возвращается как `custom`.
- **Ошибки:** `400` (text/plain) при некорректном JSON или если сохранённый `profile` приложения неизвестен. `404`, если приложения не существует. `422` / `503`, если apply не удался и изменение отменено. `500` при ошибке базы данных.

### `PATCH /api/v1/applications/{id}/security`
Накладывает частичный JSON-объект на сохранённый объект безопасности (только ключи верхнего уровня; `config.MergeApplicationSecurityJSON`), затем применяет (метка аудита `api-application-security`). Опущенные ключи сохраняют прежние значения.
- **Тело запроса:** любое подмножество полей `ApplicationSecurity`, например `{"geoip_enabled": true, "geoip_policy": "deny", "geoip_country_list": ["CN"]}`. Не более 1 MiB.
- **Ответ:** `200`, объединённый `config.ApplicationSecurity`.
- **Ошибки:** `400` (text/plain) при некорректном JSON, несовпадении типов или неизвестном сохранённом профиле. `404`, если приложения не существует. `413` (text/plain, `request body exceeds 1048576 bytes`) для тела больше 1 MiB. `422` / `503`, если apply не удался и изменение отменено. `500` при ошибке базы данных.

### `POST /api/v1/applications/{id}/security/mode`
Применяет пресет в один клик (`profiles.ApplyModePreset`), затем применяет изменения к HAProxy (метка аудита `api-application-security-mode`). При успехе пишет строку аудита `app_security_mode_changed`. Её детали: `app_id`, `app_name`, `from`, `to` и итоговые `toggles`, плюс `level: "warn"` для `reverse-proxy-only`.

Что делает каждый пресет:
- `full`: включает все переключатели и устанавливает `profile` приложения в `strict`.
- `balanced`: включает все переключатели, кроме GeoIP, и устанавливает `profile` в `balanced`.
- `trusted-lan`: выключает path ACL, базовый WAF, защиту от ботов и GeoIP и устанавливает `profile` в `trusted-lan`.
- `reverse-proxy-only`: выключает все переключатели и не трогает `profile`.
- `custom`: устанавливает `mode` в `custom` и не трогает переключатели и `profile`. В отличие от PUT и PATCH, режим не определяется заново, поэтому остаётся `custom`, даже если переключатели совпадают с каким-либо пресетом.

Политику GeoIP, список стран и переопределения rate limit пресеты никогда не меняют.
- **Тело запроса:** `{"mode": "trusted-lan"}`. `mode` обязателен и сопоставляется без учёта регистра после обрезки пробелов.
- **Ответ:** `200`, итоговый `config.ApplicationSecurity`.
- **Ошибки:** `400` (text/plain) при некорректном JSON, `unknown mode` или неизвестном профиле. `404`, если приложения не существует. `422` / `503`, если apply не удался и изменение отменено. `500` при ошибке базы данных.

## Apply и ревизии

### `POST /api/v1/apply`
Генерирует полную конфигурацию HAProxy из базы данных и применяет её. Это означает валидацию через `haproxy -c`, продвижение управляемого набора артефактов, сохранение снимка ревизии, перезагрузку HAProxy и запись ревизии конфигурации вместе со строкой аудита `apply` за один шаг. При любом сбое предыдущие файлы восстанавливаются. Именно этот эндпоинт вводит в действие изменения сертификатов, настроек, IP-списков и user agent; соответствующие эндпоинты записи сами по себе ничего не применяют.
- **Тело запроса:** необязательное `{"label": "string"}`. Метка сохраняется вместе с ревизией. Отсутствующее или некорректное тело игнорируется, и метка тогда пуста.
- **Ответ:** `200` `{"status": "applied"}`
- **Ошибки (text/plain, сообщение об ошибке движка):**
  - `422` при сбое apply, например `validation failed: …`, пустой TLS crt-list (`TLS: crt-list would be empty — …`) или сбой перезагрузки.
  - `503`, когда apply превысил время ожидания. Он ждёт не более 2 минут, включая ожидание блокировки apply (`acquire HAProxy apply lock: context deadline exceeded`). Повтор может пройти успешно.

### `GET /api/v1/revisions`
Перечисляет ревизии конфигурации HAProxy, новые первыми.
- **Параметры запроса:** `limit` (целое, по умолчанию 30). Значения ≤ 0 и всё, что не является целым числом, заменяются на 30. Значения больше 200 ограничиваются 200.
- **Ответ:** `200`, массив. `[]`, если ревизий нет.
  ```json
  [{"id": 42, "sha": "<sha256 hex>", "label": "api-application", "created_at": "2026-10-19T08:12:03.123456Z",
    "is_current": true, "config_snippet_preview": "global log stdout ..."}]
  ```
  `label` — метка, сохранённая с ревизией: `label`, переданный в `POST /apply` (пусто, если не передан), метка аудита автоматически применяемого изменения, например `api-application`, или `rollback from <sha[:12]>`. `is_current` равно true, когда `sha` совпадает с SHA-256 действующего `haproxy.cfg`. `config_snippet_preview` содержит первые 240 символов `<state_dir>/revisions/haproxy-<sha[:12]>.cfg`, где переводы строк схлопнуты в пробелы, а при обрезке добавлено `…`. Если файла нет, это пустая строка.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/revisions/{id}/rollback`
Восстанавливает управляемый набор артефактов более ранней ревизии, затем валидирует его, перезагружает HAProxy и записывает новую ревизию с меткой `rollback from <sha[:12]>` вместе со строкой аудита `rollback`. Детали этой строки аудита включают `from_revision_id` и `from_label`. Ревизии с манифестом артефактов восстанавливают полный набор артефактов. Устаревшие ревизии без манифеста восстанавливают только `haproxy.cfg`. При сбое предыдущие файлы восстанавливаются. Откат ждёт не более 2 минут, включая ожидание блокировки. Тела запроса нет.
- **Параметры пути:** `id` — положительный целочисленный ID ревизии.
- **Ответ:** `200` `{"status": "ok"}`
- **Ошибки:**
  - `400` (text/plain): `invalid revision id` для `id`, не являющегося положительным целым числом.
  - `404` (text/plain): `revision not found`.
  - `422` (text/plain): откат не удался — отсутствует снимок, не совпала контрольная сумма, `validation failed: …`, сбой перезагрузки или `already using this configuration` (только для устаревших ревизий с одним cfg). Предыдущие файлы возвращены на место.
  - `503` (text/plain): превышено время ожидания, обычно в ожидании завершения другого apply; повтор может пройти успешно.

Откат меняет только файлы HAProxy. База данных (приложения, настройки) остаётся как есть, поэтому следующий apply или следующее изменение через API, которое его запускает, снова сгенерирует конфигурацию из текущего состояния базы.

## Сертификаты

Эндпоинты сертификатов пишут только в базу данных. В отличие от эндпоинтов приложений, ни один из них не запускает apply HAProxy. Изменённый сертификат попадает на edge при следующем apply — это может быть ручной `POST /api/v1/apply`, изменение приложения или `easy-waf-acmed` после выпуска.

### `GET /api/v1/certificates/summary`
Представление для дашборда: счётчики статусов плюс по одной компактной строке на сертификат. Статус вычисляется в момент запроса (UTC).
- **Ответ:** `200`, `config.CertificateSummaryResponse`:
  - `total`, `valid`, `expiring_soon`, `expired`, `failed` (int). Строки `pending` учитываются только в `total`.
  - `certificates`: массив `config.CertificateSummaryEntry`, отсортированный по `primary_domain`, со следующими полями:
    - `id`, `primary_domain`
    - `not_after` (RFC 3339, опускается, если неизвестно)
    - `days_remaining` (int, целая часть числа дней до `not_after` с округлением вниз; отрицательно после истечения; опускается, если неизвестно)
    - `status`: `valid`, `expiring`, `expired`, `pending` или `failed`
    - `mode`: `http-01`, `dns-01` или `manual`. Любой сохранённый режим, кроме ACME, включая `self-signed`, отображается как `manual`.
    - `last_error`, `next_attempt_at`: только когда `status` равен `failed`.
- **Правила статуса, по порядку:**
  1. `not_after` в прошлом → `expired`.
  2. `acme_status` равен `pending` или `issuing` → `pending`.
  3. `acme_status` равен `failed` → `failed`, даже если более старый сертификат ещё действителен.
  4. Нет `not_after` → `pending`.
  5. Осталось меньше 30 дней → `expiring`.
  6. Иначе → `valid`.
- **Пример:**
  ```json
  {"total":2,"valid":1,"expiring_soon":0,"expired":0,"failed":1,
   "certificates":[
    {"id":"c1","primary_domain":"app.example.com","not_after":"2027-01-10T08:00:00Z","days_remaining":82,"status":"valid","mode":"http-01"},
    {"id":"c2","primary_domain":"nas.example.com","status":"failed","mode":"dns-01","last_error":"dns: timeout","next_attempt_at":"2026-10-19T14:00:00Z"}]}
  ```
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `GET /api/v1/certificates`
Перечисляет все строки сертификатов, упорядоченные по `primary_domain`.
- **Ответ:** `200`, JSON-массив `config.Certificate` (`internal/config/types.go`); `[]`, если сертификатов нет. Поля:
  - `id`, `primary_domain`, `san` (string[], опускается, если пусто)
  - `mode` (`http-01`, `dns-01`, `self-signed`, …)
  - `dns_provider`, `dns_credentials_env_file`
  - `acme_status` (`ready`, `pending`, `issuing` или `failed`), `acme_attempts`, `acme_next_attempt_at`
  - `staging` (bool)
  - `pem_crt_path`, `pem_key_path`, `fullchain_path`
  - `not_before`, `not_after`, `last_error`
  - `created_at`, `updated_at`

  `bundle_path` не хранится, поэтому никогда не возвращается.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/certificates`
Создаёт или обновляет (upsert) одну строку сертификата по ключу `id`.
- **Тело запроса:** объект `config.Certificate`. Обработчик не требует ни одного поля в обязательном порядке.
  - `id`: опустите или передайте `""`, чтобы создать новую строку со сгенерированным UUID. Если указан, должен соответствовать `^[A-Za-z0-9][A-Za-z0-9_-]*$` и быть не длиннее 128 байт.
  - `pem_crt_path`, `pem_key_path`, `bundle_path`, `fullchain_path`: необязательны. Если заданы, каждый может содержать только `[A-Za-z0-9._~+@:/-]`, не должен содержать сегмент `..` и должен быть не длиннее 4096 символов. Абсолютность пути не проверяется. `bundle_path` валидируется, но не сохраняется.
  - `dns_provider`: пробелы обрезаются, значение сохраняется в нижнем регистре. Для сертификата `dns-01` должен быть пустым (что означает значение по умолчанию, `cloudns`), `cloudflare`, `cloudns`, `route53` или `webhook`.
  - `dns_credentials_env_file`: для сертификата `dns-01` — пусто или чистый абсолютный путь (без сегментов `.`/`..`, без повторных или завершающих слэшей, без управляющих символов) строго внутри `/etc/easy-waf/` или `<state_dir>/secrets/`. `easy-waf-acmed` загружает строки `KEY=value` из этого файла в своё окружение для DNS-01-провайдера. Другие режимы ни одно из этих двух полей не используют, и там они не проверяются.
  - `acme_status`: по умолчанию `ready`, если пусто. Передача `pending` сбрасывает `acme_attempts` и `acme_next_attempt_at` в базе данных.
  - При обновлении каждый сохранённый столбец перезаписывается значением из запроса, поэтому частичное тело очищает опущенные поля. `created_at` сохраняется. `acme_attempts`, `acme_next_attempt_at` и `bundle_path` никогда не берутся из тела.
  ```json
  {"primary_domain":"app.example.com","san":["www.app.example.com"],"mode":"self-signed",
   "pem_crt_path":"/var/lib/easy-waf/certs/app.crt","pem_key_path":"/var/lib/easy-waf/certs/app.key"}
  ```
- **Ответ:** `200`, сохранённый `config.Certificate`, перечитанный после записи.
- **Ошибки (text/plain):**
  - `400` при некорректном JSON, недопустимом `id`, небезопасном пути, неподдерживаемом `dns_provider` (`dns_provider "…" is not supported (use cloudflare, cloudns, route53 or webhook)`) или отклонённом `dns_credentials_env_file` (`… must be a clean absolute path`, `… must be under /etc/easy-waf/ or <state_dir>/secrets/`).
  - `500` при ошибке базы данных.

### `DELETE /api/v1/certificates/{id}`
Удаляет строку сертификата. Отказывает, пока на сертификат ещё ссылается какое-либо приложение.
- **Параметры пути:** `id` — ID сертификата.
- **Ответ:** `204`, пустое тело.
- **Ошибки:**
  - `409` (JSON) с `{"error":"<n> application(s) still reference this certificate; detach or delete them first"}`.
  - `404` (text/plain, `not found`), когда строки с таким ID нет.
  - `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/certificates/{id}/request-issue`
Ставит в очередь выпуск или продление через ACME. Обработчик устанавливает `acme_status` в `pending` и сохраняет строку, что также сбрасывает `acme_attempts` и `acme_next_attempt_at`. `easy-waf-acmed` забирает строки в состоянии pending при следующем проходе. Сам запрос никакой работы с ACME не выполняет.
- **Параметры пути:** `id` — ID сертификата.
- **Тело запроса (необязательно):** пустое тело оставляет сохранённые настройки, как описано для каждого поля.
  - `mode` (string): `http-01` или `dns-01`, без учёта регистра. Если опущен, сохранённый режим остаётся, если он уже `http-01` или `dns-01`. Иначе по умолчанию берётся `http-01`, так что вызов означает «начать выпуск этого сертификата через ACME».
  - `dns_provider` (string): перезаписывает сохранённое значение, только если не пуст.
  - `dns_credentials_env_file` (string): перезаписывает сохранённое значение, только если не пуст.

  Если итоговый режим — `dns-01`, его DNS-поля валидируются по тем же правилам, что и в `POST /certificates`; `dns_provider` сохраняется в нижнем регистре.
  ```json
  {"mode":"dns-01","dns_provider":"cloudflare","dns_credentials_env_file":"/etc/easy-waf/dns-cloudflare.env"}
  ```
- **Ответ:** `200`, обновлённый `config.Certificate` с `acme_status: "pending"`.
- **Ошибки (text/plain):**
  - `400` при некорректном JSON, `mode must be http-01 or dns-01` для любого другого режима или отклонённом `dns_provider` / `dns_credentials_env_file`.
  - `404` (`not found`) для неизвестного ID.
  - `500` при ошибке базы данных.

## Настройки

Глобальные настройки хранятся в базе данных одним JSON-документом. Тип Go — `config.GlobalSettings` в `internal/config/types.go`; значения по умолчанию — в `config.DefaultSettings`.

Сохранение настроек обновляет базу данных и копию в памяти этого процесса, а также перенастраивает GeoIP-рантайм внутри процесса. Apply HAProxy оно **не** запускает. Настройки, влияющие на edge (правила WAF, пути map-файлов, применение GeoIP, IP-списки, …), вступают в силу при следующем `POST /api/v1/apply` или при следующем изменении приложения, которое применяется автоматически. ACL управляющей плоскости и `prometheus_enabled` читаются при каждом запросе, поэтому вступают в силу немедленно.

### `GET /api/v1/settings`
Возвращает текущие глобальные настройки.
- **Ответ:** `200`, все JSON-поля `config.GlobalSettings` плюс `crowdsec_lapi_key_set` (bool). Сам ключ CrowdSec LAPI никогда не возвращается. Длительности (`geoip_cache_ttl`, `acme_renewal_interval`) — строки длительности Go, например `"24h0m0s"`.
  ```json
  {"acme_staging":true,"crowdsec_lapi_url":"http://127.0.0.1:8080/","haproxy_config_path":"/var/lib/easy-waf/haproxy/haproxy.cfg",
   "geoip_enabled":false,"geoip_provider":"ipinfo","geoip_cache_ttl":"24h0m0s","management_allowed_cidrs":["127.0.0.0/8","::1/128","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"],
   "prometheus_enabled":false,"crowdsec_lapi_key_set":true, "...": "..."}
  ```

### `PUT /api/v1/settings` and `PATCH /api/v1/settings`
Оба метода ведут себя одинаково: они **накладывают** тело на сохранённые настройки. `PUT` не заменяет документ целиком.
- **Семантика слияния:**
  - Тело должно быть одним JSON-объектом размером не более 1 MiB; данные после него отклоняются.
  - Применяются только ключи, присутствующие в теле. Опущенные ключи сохраняют прежние значения, неизвестные ключи игнорируются.
  - Слияние начинается с настроек, хранящихся в базе данных, а не с кэшированной копии этого процесса, и выполняется под блокировкой. Поэтому параллельное изменение, сделанное через admin CLI или другим экземпляром, сохраняется.
- **Тело запроса:** любое подмножество JSON-ключей `config.GlobalSettings`, плюс доступный только для записи `crowdsec_lapi_key`. Длительности принимаются как строка длительности Go (`"12h"`) или число наносекунд. Пример:
  ```json
  {"geoip_enabled":true,"geoip_provider":"maxmind","geoip_mmdb_path":"/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb","geoip_default_policy":"deny","geoip_country_list":["CN","RU"]}
  ```
- **Поля с особой обработкой:**
  - `crowdsec_lapi_key` (только запись): пустая строка оставляет сохранённый ключ без изменений, поэтому очистить ключ через этот API нельзя. `crowdsec_lapi_key_set` в ответе показывает, сохранён ли ключ.
  - `acme_email`: пустая строка сохраняет прежнее значение, поэтому очистить адрес через этот API нельзя.
  - `management_allowed_cidrs`: `null` сохраняет прежний список. В остальных случаях список должен содержать хотя бы один элемент, и каждый элемент должен быть допустимым CIDR-префиксом (`netip.ParsePrefix`, поэтому голый IP без `/n` отклоняется). Новый список действует начиная со следующего запроса. Список, не включающий ваш собственный адрес, закроет вам доступ к API и UI.
  - `prometheus_enabled`: немедленно включает или выключает `GET /metrics`.
  - GeoIP:
    - `geoip_default_policy` должен быть `allow`, `deny` или пустым.
    - `geoip_provider` должен быть `ipinfo`, `maxmind` или пустым.
    - Когда `geoip_enabled` равно `true`, а провайдер — `maxmind`, `geoip_mmdb_path` обязателен.
  - Обязательные абсолютные пути (непустые, абсолютные, безопасные для генерации конфигурации): `haproxy_config_path`, `haproxy_stats_socket_path`, `haproxy_binary`, `geoip_enforce_map_path`, `ip_blacklist_map_path`, `ip_allowlist_map_path`, `blocked_user_agents_map_path`.
  - `spoe_config_path`: если задан, должен быть абсолютным.
  - `geoip_mmdb_path` и `spoe_config_path` также должны быть безопасны для генерации конфигурации: только `[A-Za-z0-9._~+@:/-]` и без `..`.
  - `crowdsec_engine_name`: если задан, 1–64 символа из `[A-Za-z0-9_.-]`.
  - `acme_internal_http`: пусто, что означает значение по умолчанию `127.0.0.1:8089`, или литерал `IP:port`. Имена хостов отклоняются.
  - `crowdsec_lapi_url`: если задан, должен пройти валидатор URL CrowdSec LAPI.
- **Ответ:** `200`, полные объединённые настройки той же формы, что и у `GET /api/v1/settings`.
- **Ошибки (text/plain):**
  - `400` при нечитаемом теле, некорректном JSON или неверном типе значения (сообщение начинается с ключа, например `geoip_enabled: json: cannot unmarshal ...`) либо при любом провале валидации из списка выше.
  - `413` (`request body exceeds 1048576 bytes`) для тела больше 1 MiB.
  - `500`, когда не удаётся прочитать или сохранить хранимые настройки.

### `PUT /api/v1/settings/management-tls`
Заменяет TLS-сертификат управляющего HTTPS-листенера. Обработчик проверяет, что сертификат и ключ составляют пару, атомарно записывает оба файла (сертификат с режимом `0644`, ключ — `0600`) и подменяет сертификат в памяти. Новые TLS-рукопожатия используют его сразу, без перезапуска. В базе данных ничего не сохраняется.
- **Тело запроса:**
  - `certificate_pem` (string, обязательно): PEM-сертификат, при необходимости с цепочкой.
  - `private_key_pem` (string, обязательно): закрытый ключ в PEM.
  ```json
  {"certificate_pem":"-----BEGIN CERTIFICATE-----\n...","private_key_pem":"-----BEGIN PRIVATE KEY-----\n..."}
  ```
- **Ответ:** `200` с `{"status":"ok"}`.
- **Ошибки:**
  - `400` (JSON) с `{"error":"HTTPS management is disabled (EASY_WAF_MANAGEMENT_HTTPS=0)"}`, когда листенер работает без TLS.
  - `400` (JSON) с `{"error":"certificate_pem and private_key_pem required"}`.
  - `400` (JSON) с `{"error":"invalid pem pair: ..."}` для некорректной или несовпадающей пары.
  - `400` (text/plain) при некорректном JSON.
  - `500` (JSON), когда не удаётся записать файл сертификата или ключа.

## Статистика

Оба эндпоинта читают `show stat` HAProxy из Unix-сокета статистики. Сокет — `haproxy_stats_socket_path` из настроек; пустое значение или устаревший `<state_dir>/haproxy/admin.sock` сопоставляются с `/run/haproxy/easy-waf-admin.sock`. Чтения кэшируются на 5 секунд для каждого пути сокета, а параллельные запросы используют одно общее чтение сокета. Недоступный сокет **не** является HTTP-ошибкой: оба эндпоинта всё равно возвращают `200` со строкой `error` в теле.

### `GET /api/v1/stats/haproxy`
Статистика HAProxy по каждому фронтенду и бэкенду.
- **Ответ:** `200`, `metrics.HAProxyReport` (`internal/metrics/haproxy.go`):
  - `collected_at` (RFC 3339; нулевое время, если чтение не удалось)
  - `frontends`: массив объектов с `name`, `status`, `sessions_cur`, `sessions_max`, `bytes_in`, `bytes_out`, `req_rate`, `http_2xx`, `http_4xx`, `http_5xx` и `total_req_hint` (сумма накопительных счётчиков `hrsp_*`).
  - `backends`: массив объектов с теми же счётчиками (кроме `total_req_hint`) плюс `health` (`healthy`, `degraded` или `down`, выводится из состояния серверов) и `servers` (у каждого — `name`, `status`, `sessions_cur`).
  - `error` (string, только при сбое, например `stats socket "/run/haproxy/easy-waf-admin.sock": dial unix ...: connect: no such file or directory`). При сбое `frontends` и `backends` равны `null`.
- **Ошибки:** HTTP-ошибкой ничего не возвращается. Если клиент отключился, пока ждал чтения, ничего не записывается.

### `GET /api/v1/stats/summary`
Агрегат для дашборда, вычисленный из того же отчёта.
- **Ответ:** `200`, `metrics.SummaryReport`:
  - `total_requests`: сумма `total_req_hint` по всем фронтендам, т. е. накопленное число HTTP-ответов с момента последнего сброса счётчиков HAProxy.
  - `blocked_requests`: `http_4xx + http_5xx` на фронтенде `fe_https` или на всех фронтендах, если `fe_https` нет. Учитываются все ответы 4xx и 5xx, включая пришедшие от бэкендов, а не только отказы WAF.
  - `active_sessions`: сумма `sessions_cur` фронтендов.
  - `req_rate` (float): сумма `req_rate` фронтендов.
  - `backends_up`, `backends_down`: число **серверов** бэкендов, а не бэкендов. Сервер со статусом `UP` (включая переходный `UP n/m`) считается работающим; сервер, статус которого содержит `DOWN` или начинается с `MAINT` или `NOLB`, — неработающим; прочие состояния не учитываются.
  - `error` (string, только если чтение сокета не удалось; счётчики тогда равны `0`).
  ```json
  {"total_requests":184220,"blocked_requests":312,"active_sessions":7,"req_rate":3,"backends_up":4,"backends_down":0}
  ```
- **Ошибки:** как у `/stats/haproxy`.

## Журнал аудита

### `GET /api/v1/audit`
Перечисляет строки журнала аудита, новые первыми (по убыванию `id`). Каждый изменяющий запрос к защищённому сессией API (`POST`/`PUT`/`PATCH`/`DELETE`) попадает сюда с действием `"<METHOD> <path>"` и `details` `{"http_status":<code>,"category":"<area>"}`, наряду с именованными записями, которые пишут обработчики и другие компоненты.
- **Параметры запроса:**

  | Параметр | Тип | Значение |
  |---|---|---|
  | `limit` | int | Размер страницы. По умолчанию `100`, максимум `500`. Значения `<= 0` и нечисловые заменяются на `100`. |
  | `before_id` | int64 > 0 | Курсор keyset-пагинации: только строки с `id < before_id`. Рекомендуется для постраничного чтения. |
  | `offset` | int | Устаревшая пагинация по смещению, применяется после фильтров и курсора. Отрицательные и нечисловые значения становятся `0`. Чем дальше страница, тем медленнее. |
  | `user` | string | Поиск подстроки в `user_name` без учёта регистра. |
  | `action` | string | Поиск подстроки в `action` без учёта регистра, например `certificates` или `PUT /api/v1/settings`. Значение `all` (в любом регистре) отключает фильтр. |
  | `from` | RFC 3339 | Нижняя граница времени записи, включительно. |
  | `to` | RFC 3339 | Верхняя граница времени записи, **не включительно**. |
  | `include_total` | `1` или `true` | Дополнительно вернуть `total`. Выполняет полный `COUNT(*)` и дорого обходится на больших таблицах. |

  Фильтры `user` и `action` сопоставляются буквально: `%` и `_` в значении не работают как подстановочные символы.
- **Ответ:** `200`:
  - `entries`: массив `config.AuditLogEntry`, у каждой записи — `id`, `timestamp` (RFC 3339), `user_name`, `action`, `details` (сырой JSON, `null`, если нет), `source_ip`. Всегда массив, никогда не `null`.
  - `limit`, `offset` (int): фактические значения после ограничения.
  - `has_more` (bool): за пределами этой страницы есть ещё подходящие строки. Сервер определяет это, читая одну лишнюю строку, без запроса на подсчёт.
  - `next_before_id` (int64): присутствует, только когда `has_more` равно `true`; это `id` последней записи. Передайте его как `before_id`, чтобы получить следующую страницу, сохранив те же фильтры.
  - `total` (int64): присутствует только с `include_total`. Считает строки, подходящие под фильтры **и** `before_id`, без учёта `offset`. На последующих страницах это число строк, оставшихся начиная с курсора, а не общее количество, поэтому запрашивайте его на первой странице.
- **Пример пагинации:**
  ```
  GET /api/v1/audit?limit=50&action=certificates
  → {"entries":[{"id":9812,...}, ..., {"id":9701,...}],"limit":50,"offset":0,"has_more":true,"next_before_id":9701}
  GET /api/v1/audit?limit=50&action=certificates&before_id=9701
  → {"entries":[...],"limit":50,"offset":0,"has_more":false}
  ```
- **Ошибки (text/plain):**
  - `400` для `invalid before_id (positive integer)`, `invalid from (use RFC3339)` или `invalid to (use RFC3339)`.
  - `500` при ошибке базы данных, включая неудавшийся подсчёт.

## Диагностика

### `POST /api/v1/diagnostics/bundle`
Собирает на сервере пакет для поддержки и возвращает его как tar, сжатый gzip. В худшем случае это может занять несколько минут: сервер последовательно выполняет множество локальных команд с таймаутом до 45 с на команду, включая `journalctl`, `systemctl status`, `haproxy -c` и `nft list ruleset`, и общего дедлайна, кроме контекста запроса, нет.
- **Тело запроса:** нет. Любое тело игнорируется.
- **Содержимое пакета** (всё внутри `easy-waf-diag-api-<UTC stamp>/`):
  - `MANIFEST.txt` с версией и именем хоста.
  - Сведения о системе: uname, os-release, free, df, uptime, `ss -tlnp`, статус AppArmor.
  - `systemctl status` и `is-enabled` для `easy-waf-api`, `easy-waf-acmed`, `easy-waf-hostd`, `haproxy`, `crowdsec`, `fail2ban` и `nftables`.
  - Журнал за последние 24 ч (до 500 строк на каждый) для `easy-waf-api`, `easy-waf-acmed`, `easy-waf-hostd` и `haproxy`. Строки журнала не маскируются.
  - `/etc/easy-waf/easy-waf.env` с замаскированными секретами.
  - Сгенерированный `haproxy.cfg` — читается, только если лежит внутри `<state_dir>/haproxy/`.
  - Только имена файлов crt-list, без ключей.
  - Вывод `haproxy -vv` и `haproxy -c`.
  - Последние 5 ревизий конфигурации (id, sha256, время).
  - Набор правил nftables и `/etc/nftables/easy-waf.nft`.
- **Ответ:** `200`, `Content-Type: application/gzip`, `Content-Disposition: attachment; filename="easy-waf-diag-api-YYYYMMDD-HHMMSS.tar.gz"`. Тело — байты `.tar.gz`.
- **Ошибки (JSON):** `500` с `{"error":"..."}`, когда пакет не удаётся собрать. Например, несжатый tar больше 40 MiB (`diagnostics: bundle size N exceeds limit 41943040`) или ошибка записи tar. Сбой отдельной команды не приводит к ошибке запроса; её вывод (или ничего) попадает в файл.

## Блоклист IP (IPBL)

Ни один из эндпоинтов записи для блоклиста IP, allowlist IP или блокируемых user agent не применяет изменение к HAProxy; они пишут только в базу данных. Изменение попадает в HAProxy при следующем `POST /api/v1/apply` (или при следующем изменении приложения, которое применяется автоматически). `POST /api/v1/ipbl/sync` переписывает map-файлы, но не перезагружает HAProxy, а HAProxy читает map-файлы при (пере)загрузке.

### `GET /api/v1/ipbl/local`
Перечисляет все локальные записи блоклиста, включённые и выключенные, упорядоченные по `cidr`.
- **Ответ:** `200`, массив записей; `[]`, если записей нет:
  ```json
  [
    {
      "id": "6f1c0e8a-3c55-4a43-9a43-0c1f2b8f0d11",
      "cidr": "203.0.113.0/24",
      "note": "scanner range",
      "enabled": true,
      "created_at": "2026-10-01T12:00:00Z",
      "updated_at": "2026-10-01T12:00:00Z"
    }
  ]
  ```
  `note` опускается, если пусто.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/ipbl/local`
Создаёт или обновляет локальную запись блоклиста. Это upsert по ключу `id`: без `id` (или с пустым) назначается новый UUID и вставляется строка. С `id` обновляется строка с этим id, а если её нет — вставляется под этим id.
- **Тело запроса** (JSON, `config.IPBLLocalEntry`):

  | Поле | Тип | Примечания |
  |---|---|---|
  | `id` | string | необязательно; опустите, чтобы создать |
  | `cidr` | string | **обязательно**; пробелы обрезаются; должен быть допустимым IP-адресом или CIDR (`net.ParseIP` / `net.ParseCIDR`) |
  | `note` | string | необязательно |
  | `enabled` | bool | по умолчанию `true`, если опущено |

  `updated_at` устанавливает сервер. При обновлении сохранённый `created_at` остаётся в базе данных прежним.

  ```json
  { "cidr": "198.51.100.7", "note": "brute force" }
  ```

- **Ответ:** `200` с сохранённой записью, включая назначенный `id` и её `created_at`.
- **Ошибки (text/plain):** `400` при некорректном JSON, `cidr required` (пусто после обрезки) или недопустимом IP/CIDR (`invalid ip or cidr` либо ошибка разбора CIDR из Go). `500` при ошибке базы данных.

### `DELETE /api/v1/ipbl/local/{id}`
Удаляет локальную запись блоклиста.
- **Параметры пути:** `id` — id записи.
- **Ответ:** `204`, без тела.
- **Ошибки (text/plain):** `404` (`not found`) для неизвестного id. `500` при ошибке базы данных.

### `GET /api/v1/ipbl/sources`
Перечисляет внешние фиды блоклистов, упорядоченные по `name`.
- **Ответ:** `200`, массив; `[]`, если фидов нет:
  ```json
  [
    {
      "id": "b0b5c2c4-0f7e-4f0e-9a51-1d0c7c6f8a22",
      "name": "spamhaus-drop",
      "url": "https://www.spamhaus.org/drop/drop.txt",
      "enabled": true,
      "refresh_seconds": 3600,
      "last_fetch_at": "2026-10-19T08:00:00Z",
      "last_error": "",
      "created_at": "2026-10-01T12:00:00Z",
      "updated_at": "2026-10-19T08:00:00Z"
    }
  ]
  ```
  `last_fetch_at` и `last_error` опускаются, если не заданы. Их пишет только загрузчик фидов во время sync/apply.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/ipbl/sources`
Создаёт или обновляет внешний фид. Это upsert по ключу `id` с той же семантикой, что и у `POST /ipbl/local`. Фид при этом не загружается; загрузка происходит при sync/apply.
- **Тело запроса** (JSON, `config.IPBLExternalSource`):

  | Поле | Тип | Примечания |
  |---|---|---|
  | `id` | string | необязательно; опустите, чтобы создать |
  | `name` | string | отображаемое имя, не валидируется |
  | `url` | string | обязательно; только `http` или `https`; проверяется защитой от SSRF (ниже) |
  | `enabled` | bool | по умолчанию `true`, если опущено |
  | `refresh_seconds` | int | `<= 0` или отсутствие сохраняется как `3600` |

  `last_fetch_at` и `last_error` в теле игнорируются: новый источник начинает без них, а при обновлении сохраняются прежние значения.

  ```json
  { "name": "firehol-level1", "url": "https://iplists.firehol.org/files/firehol_level1.netset", "refresh_seconds": 86400 }
  ```

  **Валидация URL:** URL разбирается, схема должна быть `http`/`https`. Хост резолвится, и **каждый** полученный адрес (или литеральный IP) должен пройти SSRF-политику для фидов. Loopback, link-local (включая адреса метаданных `169.254.x`), CGNAT `100.64.0.0/10` и неуказанные адреса отклоняются всегда. Частные адреса (RFC 1918) отклоняются, если только они не попадают в `ipbl_fetch_allowed_cidrs` либо не включён устаревший `ipbl_allow_private_fetch` при пустом списке. Имя хоста должно резолвиться в момент сохранения.

- **Ответ:** `200` с сохранённым источником (та же форма, что у элементов списка), включая его текущий статус загрузки.
- **Ошибки:** `400` (JSON) `{"error": "..."}`, когда URL не прошёл валидацию (неверная схема, сбой DNS, запрещённое назначение). `400` (text/plain) при некорректном JSON. `500` (text/plain) при ошибке базы данных.

### `DELETE /api/v1/ipbl/sources/{id}`
Удаляет внешний фид. Его сохранённая копия на диске удаляется при следующем sync или apply.
- **Параметры пути:** `id` — id источника.
- **Ответ:** `204`, без тела.
- **Ошибки (text/plain):** `404` (`not found`) для неизвестного id. `500` при ошибке базы данных.

### `POST /api/v1/ipbl/sync`
Заново генерирует IP map-файлы на диске — под блокировкой apply движка и с настройками, хранящимися в базе данных на текущий момент. Шаги:

1. Объединить включённые локальные записи блоклиста.
2. Если `ipbl_external_enabled` равно true, скачать каждый включённый внешний фид через загрузчик с защитой от SSRF. Каждый фид ограничен 16 MiB и 250 000 записей. При неудачной загрузке используется последняя удачная копия этого фида, но не старше 7 дней; сбойный фид не приводит к ошибке sync. Результат загрузки записывается в каждый источник (`last_fetch_at`, `last_error`). Сохранённые копии удалённых или выключенных источников удаляются. Если внешние фиды выключены, удаляются все сохранённые копии фидов.
3. Записать map-файл блоклиста (`ip_blacklist_map_path`, по умолчанию `<state>/haproxy/ip_blacklist.map`).
4. Переписать map-файл allowlist из `ipwl_local`.
5. Переписать map-файл применения GeoIP (или его заглушку, если GeoIP выключен).

Конфигурацию HAProxy он **не** генерирует и HAProxy не перезагружает.

- **Тело запроса:** нет.
- **Ответ:** `200`, `ipbl.SyncResult`:

  ```json
  {
    "local_lines": 12,
    "external_lines": 48210,
    "total_lines": 47987,
    "map_path": "/var/lib/easy-waf/haproxy/ip_blacklist.map"
  }
  ```

  `local_lines` — число уникальных допустимых локальных записей. `external_lines` — число объединённых строк фидов, посчитанное по каждому фиду с учётом дубликатов. `total_lines` — число уникальных строк, записанных в `map_path`.
- **Ошибки:** `500` (text/plain) при любом сбое: блокировка, перечитывание настроек, база данных, запись файла или map-файл GeoIP.

## Allowlist IP

### `GET /api/v1/ipwl/local`
Перечисляет локальные записи allowlist, упорядоченные по `cidr`.
- **Ответ:** `200`, массив; `[]`, если записей нет:
  ```json
  [
    { "id": "1d7c...", "cidr": "192.168.1.0/24", "comment": "office LAN", "created_at": "2026-10-01T12:00:00Z" }
  ]
  ```
  `comment` опускается, если пусто.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/ipwl/local`
Создаёт или обновляет запись allowlist. Это upsert по ключу `id` (опустите, чтобы создать). При обновлении меняются только `cidr` и `comment`; `created_at` задаёт сервер.
- **Тело запроса** (JSON, `config.IPWLLocalEntry`):

  | Поле | Тип | Примечания |
  |---|---|---|
  | `id` | string | необязательно |
  | `cidr` | string | **обязательно**; пробелы обрезаются; должен быть допустимым IP-адресом или CIDR (`net.ParseIP` / `net.ParseCIDR`) |
  | `comment` | string | необязательно |

  ```json
  { "cidr": "192.168.1.0/24", "comment": "office LAN" }
  ```

- **Ответ:** `200` с сохранённой записью.
- **Ошибки (text/plain):** `400` при некорректном JSON, `cidr required` (пусто после обрезки) или недопустимом IP/CIDR (`invalid ip or cidr` либо ошибка разбора CIDR из Go). `500` при ошибке базы данных.

Записи allowlist применяются, только когда `ipwl_enabled` равно true. Map-файл переписывается при apply и при `POST /ipbl/sync`.

### `DELETE /api/v1/ipwl/local/{id}`
Удаляет запись allowlist.
- **Параметры пути:** `id`.
- **Ответ:** `204`, без тела.
- **Ошибки (text/plain):** `404` (`not found`) для неизвестного id. `500` при ошибке базы данных.

## Блокируемые User-Agent

Шаблоны записываются в map-файл HAProxy и сопоставляются как **подстроки без учёта регистра** заголовка `User-Agent` (`-m sub -i`). Они применяются, только когда включена глобальная настройка `blocked_user_agents_enabled`, и только для приложений с включённой защитой от ботов. Свежая установка заранее заполняет несколько шаблонов сканеров (`Nmap`, `Nikto`, `sqlmap`, ...).

### `GET /api/v1/security/blocked-ua`
Перечисляет все шаблоны, упорядоченные по `pattern`.
- **Ответ:** `200`, массив; `[]`, если таблица пуста:
  ```json
  [
    { "id": "seed-nmap", "pattern": "Nmap", "comment": "scanner", "created_at": "2026-01-01T00:00:00Z" }
  ]
  ```
  `comment` опускается, если пусто.
- **Ошибки:** `500` (text/plain) при ошибке базы данных.

### `POST /api/v1/security/blocked-ua`
Добавляет шаблон. Всегда **создаёт** новую строку: любой `id` в теле игнорируется, и назначается новый UUID. Эндпоинта обновления нет; вместо этого удалите шаблон и добавьте заново.
- **Тело запроса** (JSON, `config.BlockedUserAgent`):

  | Поле | Тип | Примечания |
  |---|---|---|
  | `pattern` | string | **обязательно**; пробелы обрезаются; должен быть непустым и без управляющих символов (перевод строки, табуляция, …) |
  | `comment` | string | необязательно |

  ```json
  { "pattern": "masscan", "comment": "scanner" }
  ```

- **Ответ:** `200` с сохранённой строкой, включая её новый `id` и `created_at`.
- **Ошибки (text/plain):** `400` при некорректном JSON, `pattern required` или `pattern must not contain control characters`. `500` при ошибке базы данных.

Повторяющиеся шаблоны в базе данных допускаются. Дубликаты убираются при генерации map-файла.

### `DELETE /api/v1/security/blocked-ua/{id}`
Удаляет шаблон. У предустановленных шаблонов id вида `seed-nmap`.
- **Параметры пути:** `id`.
- **Ответ:** `204`, без тела.
- **Ошибки (text/plain):** `404` (`not found`) для неизвестного id. `500` при ошибке базы данных.

## GeoIP

### `GET /api/v1/geoip/lookup`
Определяет страну для одного IP-адреса с помощью настроенного провайдера (`ipinfo` или `maxmind`). Результаты от настроенного провайдера сохраняются в TTL-кэше в памяти (`geoip_cache_ttl`) и отдаются из него.
- **Параметры запроса:**
  - `ip` (обязательно): адрес IPv4 или IPv6.
  - `nocache` (необязательно): `1` вытесняет этот IP из кэша перед поиском, что принудительно запрашивает провайдера заново. Свежий ответ снова кэшируется.
  - `probe_mmdb_path` (необязательно): абсолютный путь к файлу `.mmdb` на appliance. Только для этого запроса он подменяет настройки на `geoip_provider=maxmind` и `geoip_mmdb_path=<path>`. База открывается только на время поиска и затем закрывается. Результат не читается из кэша и не записывается в него, а настроенный reader не заменяется. Используйте это, чтобы проверить путь перед сохранением настроек.
- **Ответ:** `200`:

  ```json
  { "ip": "8.8.8.8", "country": "US", "cached": false }
  ```

  `country` — код, возвращённый провайдером. `cached` равно true, только если ответ пришёл из кэша.
- **Ошибки (text/plain):** `400` с `ip query parameter required` или `invalid ip`. `502`, когда поиск у провайдера не удался, например когда не удаётся открыть MMDB, ipinfo недоступен или ограничивает частоту запросов, или GeoIP-рантайм не инициализирован. С ipinfo поиск может занять несколько секунд (ограничение частоты плюс HTTP-таймаут до 15 с).

### `GET /api/v1/geoip/stats`
Возвращает счётчики кэша поиска GeoIP.
- **Ответ:** `200`:

  ```json
  { "size": 128, "hits": 5402, "misses": 311 }
  ```

  Все поля равны нулю, если GeoIP-рантайм или его кэш не инициализированы.

### `GET /api/v1/geoip/providers`
Перечисляет поддерживаемых провайдеров и сообщает, можно ли использовать каждого.
- **Ответ:** `200`, всегда две строки:

  ```json
  [
    { "name": "ipinfo", "available": true },
    { "name": "maxmind", "available": true, "mmdb_path": "/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb" }
  ]
  ```

  `ipinfo` всегда `available: true`. `maxmind` — `available: true`, когда настроенный `geoip_mmdb_path` не пуст и указывает на существующий файл, не являющийся каталогом. Файл не открывается и не валидируется. `mmdb_path` — настроенный путь; опускается, если пуст.

### `POST /api/v1/geoip/reload`
Заново открывает базу MaxMind в процессе API и очищает кэш поиска. Используйте после замены файла `.mmdb` на месте.
- **Тело запроса:** необязательный JSON `{"mmdb_path": "/path/to/file.mmdb"}`. Если тело пустое или `mmdb_path` отсутствует либо пуст, используется настроенный `geoip_mmdb_path`. Обработчик читает не более 4096 байт; более длинное тело обрезается и затем не разбирается.
- **Ответ:** `200` `{"status": "ok"}`.
- **Ошибки (JSON `{"error": "..."}`):**
  - `400` `geoip_provider is not maxmind`: настроенный провайдер — не `maxmind`. Это проверяется до чтения тела.
  - `400` при некорректном JSON в теле.
  - `400` `geoip_mmdb_path is empty`: пути нет ни в теле, ни в настройках.
  - `502`: базу не удалось открыть или перезагрузить.

`mmdb_path`, отличающийся от настроенного `geoip_mmdb_path`, загружается, но рантайм привязывает свой reader к настроенному пути, поэтому обычные поиски его не используют. Вместо этого укажите этот файл в `geoip_mmdb_path`.

### `POST /api/v1/geoip/database`
Загружает и устанавливает базу MaxMind GeoLite2 (или совместимую). Этот маршрут **исключён из глобального ограничения тела в 4 MiB** и применяет собственный предел.
- **Тело запроса:** **сырые байты файла** (передавайте `Content-Type: application/octet-stream`; заголовок не проверяется). Это не multipart/form-data. Принимаются два формата, определяемые по содержимому (gzip magic `1f 8b`) и никогда — по имени файла:
  - обычный файл `.mmdb`;
  - архив MaxMind `.tar.gz`. Извлекается первый обычный файл архива, имя которого оканчивается на `.mmdb` (без учёта регистра). Остальные элементы пропускаются.

  **Ограничения:** тело запроса ограничено **128 MiB** (`geoip.MaxMMDBBytes`, на практике — 128 MiB + 1 байт). Извлечённая база также ограничена 128 MiB. Пустой ввод отклоняется.

  ```sh
  curl --data-binary @GeoLite2-Country.tar.gz \
       -H 'Content-Type: application/octet-stream' \
       https://<host>:8443/api/v1/geoip/database   # plus session/CSRF headers
  ```

- **Обработка:**
  1. Загрузки выполняются последовательно: одновременно идёт только одна установка.
  2. Файл записывается во временный файл в `<state>/geoip/`.
  3. Файл валидируется. Он должен открываться как MaxMind DB, его `database_type` должен содержать `country` или `city`, а поиск `8.8.8.8` должен вернуть страну.
  4. Файл атомарно переименовывается в `<state>/geoip/<database_type>.mmdb`. Если тип небезопасен в качестве имени файла, используется имя `GeoLite2-Country.mmdb`. Путь назначения никогда не берётся из запроса.
  5. Если `geoip_provider` равен `maxmind` **и** `geoip_mmdb_path` совпадает с путём установки, действующий reader подменяется на лету, а кэш очищается (`reloaded: true`). Иначе файл сохраняется, но не активируется, и `activate_hint` объясняет, что нужно изменить.

  Отклонённая загрузка не трогает существующую базу. Успешная установка записывает действие аудита **`geoip_database_uploaded`** с `mmdb_path`, `database_type`, `build_epoch`, `size_bytes`, `node_count` и `reloaded`.
- **Ответ:** `200`:

  ```json
  {
    "path": "/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb",
    "database_type": "GeoLite2-Country",
    "build_epoch": "2026-10-14T00:00:00Z",
    "node_count": 1234567,
    "ip_version": 6,
    "size_bytes": 9876543,
    "probe_ip": "8.8.8.8",
    "probe_country": "US",
    "reloaded": false,
    "activate_hint": "set geoip_provider=maxmind and geoip_mmdb_path=/var/lib/easy-waf/geoip/GeoLite2-Country.mmdb, then save settings"
  }
  ```

  `activate_hint` опускается, когда `reloaded` равно true.
- **Ошибки (JSON `{"error": "..."}`):**
  - `400`: данные не являются пригодной базой. Причины: пустой ввод, повреждённый поток gzip/tar, архив без элемента `.mmdb`, файл, не являющийся MaxMind DB, тип базы без данных о странах или неудачный пробный поиск.
  - `413`: тело запроса или извлечённая база больше 128 MiB.
  - `500`: не удалось создать или записать каталог GeoIP или его файлы.
  - `502` `database installed but reload failed: ...`: файл установлен, но подмена на лету не удалась. В этом случае тело также содержит `mmdb_path`.

## CrowdSec

Все эндпоинты CrowdSec обращаются к CrowdSec Local API (LAPI). URL и ключ определяются так:

- **URL:** `CROWDSEC_LAPI_URL` из окружения (`/etc/easy-waf/easy-waf.env`) имеет приоритет над настройкой `crowdsec_lapi_url`. По умолчанию — `http://127.0.0.1:8080/`.
- **Ключ:** `CROWDSEC_LAPI_KEY` из окружения имеет приоритет над сохранённым `crowdsec_lapi_key`. Он передаётся как `X-Api-Key`.

URL должен пройти allowlist назначений LAPI (по умолчанию только `http://127.0.0.1:8080` и `http://[::1]:8080`; дополнительные origin берутся из `CROWDSEC_LAPI_ALLOWED_ORIGINS`). URL, не прошедший эту проверку, сообщается как `crowdsec lapi url rejected: <reason>`; как это делает каждый эндпоинт, описано ниже. Редиректы от LAPI отклоняются.

### `GET /api/v1/integrations/crowdsec`
Проверяет, отвечает ли LAPI, отправляя ему `GET /v1/watchers/login`.
- **Ответ:** всегда `200`:

  ```json
  { "reachable": true, "last_message": "http 405" }
  ```

  `reachable` означает лишь то, что LAPI ответил HTTP-ответом, не являющимся редиректом. Ключ баунсера **не** проверяется: `401` или `403` (неверный или отсутствующий ключ) всё равно считается доступностью, а `last_message` показывает статус (`http 403`). Чтобы убедиться, что ключ работает, используйте `GET /integrations/crowdsec/decisions`. `reachable` равно false при ошибке соединения (`last_message` содержит ошибку), когда LAPI отвечает редиректом (`lapi redirect refused`) или когда URL отклонён (`crowdsec lapi url rejected: ...`). `last_message` опускается, если пусто.

### `GET /api/v1/integrations/crowdsec/decisions`
Возвращает активные решения, отправляя в LAPI `GET /v1/decisions?limit=100`.
- **Ответ:** `200`, JSON-тело LAPI **передаётся как есть** (`Content-Type: application/json`). Это массив решений CrowdSec; его поля (`id`, `value`, `type`, `duration`, `scenario`, `origin`, ...) определяет CrowdSec, а не easy-waf. Если решений нет, CrowdSec отвечает `null`, а не `[]`.
- **Ошибки:** `502` (JSON) `{"error": "..."}`, когда URL LAPI отклонён, LAPI недоступен, отвечает редиректом, возвращает статус не из 2xx (`crowdsec lapi decisions: http 403`) или присылает больше 1 MiB (`crowdsec lapi decisions: response exceeds 1048576 bytes`).

### `POST /api/v1/integrations/crowdsec/decisions`
Добавляет ручное решение для одного IP, отправляя в LAPI `POST /v1/decisions`. Запрос — массив из одного элемента с `scope: "Ip"` и `origin: "easy-waf"`, а `reason` передаётся как `scenario`. При успехе записывает действие аудита **`crowdsec.decision_added`** с `ip`, `type`, `duration` и `reason`.
- **Тело запроса** (JSON, `crowdsec.AddDecisionRequest`):

  | Поле | Тип | Примечания |
  |---|---|---|
  | `ip` | string | **обязательно**; один адрес IPv4/IPv6 (не CIDR) |
  | `type` | string | по умолчанию `ban`. `whitelist` обрабатывается особо. Прочие значения передаются в LAPI без проверки |
  | `duration` | string | см. сопоставление ниже; прочие значения (например, `30m`) передаются без изменений |
  | `reason` | string | по умолчанию `manual ban from UI` (`manual allowlist from UI` для `whitelist`) |

  Сопоставление длительностей: пустое значение или `24h` становится `24h`. `1h` и `4h` не меняются. `7d` и `168h` становятся `168h`. `permanent` становится `876000h`. Для `type: whitelist` пустое значение, `permanent` или `876000h` становится `876000h`.

  ```json
  { "ip": "203.0.113.50", "type": "ban", "duration": "168h", "reason": "manual: credential stuffing" }
  ```

- **Ответ:** `200` `{"status": "ok"}`.
- **Ошибки:**
  - `400` (text/plain) при некорректном JSON.
  - `400` (JSON), когда `ip` пуст или не является допустимым IP-адресом (`crowdsec: invalid IP address: ...`). Это проверяется первым.
  - `502` (JSON), когда URL LAPI отклонён, LAPI недоступен, отвечает редиректом или возвращает статус не из 2xx (например, `crowdsec lapi add decision: http 403` при неверном ключе).

### `DELETE /api/v1/integrations/crowdsec/decisions/{id}`
Удаляет одно решение, отправляя в LAPI `DELETE /v1/decisions/{id}`. При успехе записывает действие аудита **`crowdsec.decision_deleted`** с `decision_id`.
- **Параметры пути:** `id` — id решения в LAPI из списка решений. Перед пересылкой он экранируется для пути URL.
- **Ответ:** `204`, без тела. Успехом считаются и 200, и 204 от LAPI.
- **Ошибки (JSON):** `400` `missing decision id`. `404`, когда LAPI отвечает 404 (`crowdsec: decision not found`). `502` для любого другого сбоя: отклонённый URL, недоступность, редирект или другой статус не из 2xx.

## Fail2Ban

Все эндпоинты Fail2Ban запускают `fail2ban-client` через привилегированный брокер хоста (`easy-waf-hostd`), никогда напрямую. У каждого вызова `fail2ban-client` таймаут 12 секунд.

### `GET /api/v1/integrations/fail2ban`
Пингует демон, перечисляет его jail и получает заблокированные IP каждого jail. Выполняет `ping`, затем `status`, затем `status <jail>` для каждого jail.
- **Ответ:** `200`:

  ```json
  {
    "status": { "installed": true, "running": true, "message": "pong" },
    "jails": [
      { "name": "sshd", "banned_ips": ["198.51.100.23", "203.0.113.9"] },
      { "name": "recidive", "banned_ips": [] }
    ]
  }
  ```

  - `jails` равен `[]`, когда у демона нет jail, а `banned_ips` равен `[]`, когда в jail нет банов.
  - Если не удался статус отдельного jail, этот jail всё равно перечисляется, с `banned_ips: []`.
  - Если fail2ban не установлен: `200` с `status.installed: false`, `status.message: "fail2ban: fail2ban-client not found"`, `jails: []`.
  - Если он установлен, но демон не отвечает `pong`: `200` с `status.running: false`, выводом клиента в `status.message` и `jails: []`.
- **Ошибки:** `502` (JSON) `{"error": "...", "status": {...}}`, когда команда `status` не удалась после успешного ping. Объект `status` имеет ту же форму, что и выше, а его `message` содержит вывод команды.

### `GET /api/v1/integrations/fail2ban/jails/{jail}`
Возвращает заблокированные IP одного jail (`fail2ban-client status <jail>`).
- **Параметры пути:** `jail`, соответствующий `^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$` после обрезки пробелов.
- **Ответ:** `200` `{"name": "sshd", "banned_ips": ["198.51.100.23"]}`. `banned_ips` равен `[]`, когда в jail нет банов или вывод не удалось разобрать.
- **Ошибки (JSON):** `400` `fail2ban: invalid jail name`. `502`, когда команда не удалась. Это покрывает неизвестный jail, остановленный демон, неустановленный fail2ban и ошибки брокера; сообщение включает вывод клиента.

### `POST /api/v1/integrations/fail2ban/unban`
Убирает один IP из списка банов jail (`fail2ban-client set <jail> unbanip <ip>`). При успехе записывает действие аудита **`fail2ban.unban`** с `jail` и `ip`.
- **Тело запроса** (JSON):

  | Поле | Тип | Примечания |
  |---|---|---|
  | `jail` | string | **обязательно**; тот же шаблон, что и выше |
  | `ip` | string | **обязательно**; один адрес IPv4/IPv6 |

  ```json
  { "jail": "sshd", "ip": "203.0.113.1" }
  ```

- **Ответ:** `200` `{"status": "ok"}`.
- **Ошибки:** `400` (text/plain) при некорректном JSON. `400` (JSON) `fail2ban: invalid jail name` или `fail2ban: invalid IP address`. `502` (JSON) `fail2ban unban: <client output>`, когда команда не удалась, например для неизвестного jail или IP, который не заблокирован.

## Health-пробы и метрики

Эти три маршрута смонтированы вне `/api/v1` и не требуют сессионного JWT.

### `GET /health`
Liveness-проба. Отвечает, как только процесс может обслуживать HTTP, и не обращается к базе данных. Исключена из ACL по CIDR источника для управляющей плоскости.
- **Ответ:** `200` с `{"status":"ok"}`.
- **Ошибки:** собственных нет. Зарегистрирован только `GET`, поэтому прочие методы роутер отклоняет с `405`.

### `GET /health/ready`
Readiness-проба. Пингует PostgreSQL с таймаутом 2 секунды. Как и `/health`, исключена из ACL управляющей плоскости, поэтому никогда не возвращает подробностей ошибок.
- **Ответ:** `200` с `{"status":"ok","database":"ok"}`.
- **Ошибки (JSON):**
  - `503` с `{"status":"unavailable","database":"unreachable"}`, когда ping не удался или превысил таймаут.
  - `503` с `{"status":"unavailable","database":"not configured"}`, когда у сервера нет хранилища.

### `GET /metrics`
Текстовый формат Prometheus для серий `easy_waf_*`. Серии охватывают итоги и частоту запросов фронтендов HAProxy, сессии и состояние up/down бэкендов, оставшиеся дни сертификатов, число решений CrowdSec, число записей в IP-блоклисте, приложения по режиму безопасности и счётчики apply и ошибок apply. Управляющая плоскость обновляет значения, полученные из HAProxy, в фоне (примерно раз в 15 с), а не при каждом скрейпе. См. `metrics.PrometheusExporter` в `internal/metrics/prometheus.go`.

В отличие от `/health`, этот маршрут **подпадает** под ACL управляющей плоскости. Сессионный JWT он не принимает.
- **Аутентификация:** по умолчанию нет. Если задана переменная окружения `EASY_WAF_METRICS_TOKEN` (не короче 16 символов, читается при старте процесса), запрос должен передавать `Authorization: Bearer <token>`. Более короткий токен игнорируется с записью в лог, и эндпоинт остаётся открытым.
- **Ответ:** `200`, текстовый формат Prometheus.
- **Ошибки (text/plain):**
  - `404` (`404 page not found`), когда `prometheus_enabled` в настройках равно `false` (это значение по умолчанию) или когда экспортер не настроен.
  - `401` (`unauthorized`), когда токен метрик настроен, а bearer-значение отсутствует или неверно.
  - `405` (`method not allowed`) для методов, отличных от `GET`. На практике `POST`/`PUT`/`PATCH`/`DELETE` без `X-Requested-With` отклоняется раньше CSRF-middleware с `403` в JSON.

## Управление хостом

Маршруты `/api/v1/host/*` управляют самим хостом appliance (сеть, файрвол, службы, пакеты, питание, локальные пользователи, сетевая диагностика). Сами они команд не выполняют: каждый вызов проходит через привилегированный брокер хоста (`easy-waf-hostd`). Для изменений сети и файрвола есть процедура отката: `apply` возвращает `token` и `expires_at`, и изменение автоматически откатывается, если до истечения срока его не подтвердили через `commit`. Подробности запросов и ответов — в [HOST-API.md](HOST-API.md).

| Метод и путь | Назначение |
|---|---|
| `GET /api/v1/host/network` | Текущие интерфейсы и адреса (снимок `ip -j`) |
| `PUT /api/v1/host/network/netplan` | Записать и сразу применить YAML netplan, без отката |
| `POST /api/v1/host/network/netplan/apply` | Применить YAML netplan с автоматическим откатом; возвращает токен |
| `POST /api/v1/host/network/netplan/commit` | Подтвердить ожидающий apply netplan по токену |
| `GET /api/v1/host/firewall` | Статус и набор правил nftables |
| `PUT /api/v1/host/firewall/ruleset` | Проверить, установить и сразу применить управляемый набор правил nftables, без отката |
| `POST /api/v1/host/firewall/apply` | Загрузить установленный управляемый набор правил, без отката |
| `POST /api/v1/host/firewall/apply-rollback` | Применить набор правил с автоматическим откатом; возвращает токен |
| `POST /api/v1/host/firewall/commit` | Подтвердить ожидающий apply файрвола по токену |
| `GET /api/v1/host/services` | Список юнитов systemd из allowlist и их состояние |
| `POST /api/v1/host/services/{unit}/{action}` | Выполнить `start`, `stop`, `restart`, `reload`, `enable`, `disable` или `try-restart` для юнита из allowlist |
| `GET /api/v1/host/journal` | Прочитать строки журнала (`unit`, `since`, `until`, `priority`, `lines`) |
| `GET /api/v1/host/updates` | Список доступных обновлений пакетов |
| `POST /api/v1/host/updates/update` | Выполнить `apt update` |
| `POST /api/v1/host/updates/upgrade` | Выполнить `apt upgrade` |
| `POST /api/v1/host/updates/upgrade/stream` | Выполнить `apt upgrade` с потоковой передачей вывода в NDJSON |
| `GET /api/v1/host/updates/upgrade/log` | Вывод последнего обновления (text/plain) |
| `GET /api/v1/host/updates/upgrade/status` | Идёт ли сейчас обновление |
| `GET /api/v1/host/updates/autoremove/preview` | Пакеты, которые удалил бы `apt autoremove` |
| `POST /api/v1/host/updates/autoremove/stream` | Выполнить `apt autoremove` с потоковой передачей вывода |
| `POST /api/v1/host/updates/clean` | Выполнить `apt clean` |
| `GET /api/v1/host/disk` | Использование диска |
| `POST /api/v1/host/power/reboot` | Перезагрузить хост |
| `POST /api/v1/host/power/shutdown` | Выключить хост |
| `GET /api/v1/host/users` | Список локальных учётных записей (uid ≥ 1000, плюс `root`) |
| `POST /api/v1/host/users` | Создать локального пользователя |
| `DELETE /api/v1/host/users/{name}` | Удалить локального пользователя |
| `PUT /api/v1/host/users/{name}/ssh-keys` | Заменить авторизованные SSH-ключи пользователя |
| `POST /api/v1/host/diagnostics/ping` | Пинг цели с хоста |
| `POST /api/v1/host/diagnostics/trace` | Traceroute до цели с хоста |
