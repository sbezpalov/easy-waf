# Диагностика проблем
[English](TROUBLESHOOTING.md) | **Русский** · канонический документ — английский; при расхождении верна английская версия. Переведено с 1.4.1.

Документ соответствует релизу **1.4.1** (см. [`VERSION`](../VERSION)).

## `systemctl`: нет `crowdsec.service` / юнита SPOA-баунсера

Пакеты не были установлены (например, **`EASY_WAF_INSTALL_CROWDSEC=0`**, сбой packagecloud). По умолчанию **`scripts/install.sh`** ставит CrowdSec и SPOA-баунсер через **apt**; см. [CROWDSEC.md](CROWDSEC.md).

**SPOA-баунсер:** apt-пакет **`crowdsec-haproxy-spoa-bouncer`**, systemd-юнит **`crowdsec-spoa-bouncer.service`**. После `apt install`:

```bash
systemctl enable --now crowdsec-spoa-bouncer.service
systemctl status crowdsec-spoa-bouncer.service
```

Конфигурация баунсера: `/etc/crowdsec/bouncers/crowdsec-spoa-bouncer.yaml`.

После установки пакеты могут быть на месте, но юниты остаются **disabled**, пока не запущен LAPI: **`sudo bash scripts/crowdsec-bootstrap-lapi.sh`** или **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1 bash scripts/install.sh`** (перерегистрирует баунсеры **`easy-waf-api`** / **`easy-waf-spoa`** и ключ в **`/etc/easy-waf/easy-waf.env`**).

## Панель: все «Core services» в состоянии `unknown`

API выполняет **`/usr/bin/systemctl show -p ActiveState`** (и **`is-active`**, если требуется) от имени пользователя **`easy-waf`**.

1. Убедитесь, что на хосте **актуальный** `easy-waf-api` после `git pull` и **`systemctl restart easy-waf-api`** (см. [OPERATIONS.md](OPERATIONS.md) — UI встроен в бинарник).
2. Проверьте от имени `easy-waf`: `sudo -u easy-waf /usr/bin/systemctl show -p ActiveState --value haproxy.service` — должно выводиться `active` или `inactive`, а не пустая строка.
3. Если команда падает: **AppArmor** / отсутствует **`/usr/bin/systemctl`** либо ограничения юнита (в `easy-waf-api.service` уже есть `ReadWritePaths=/run` для D-Bus).

## `$'\r': command not found` при запуске скрипта `*.sh`

У файла **окончания строк Windows CRLF**. На устройстве:

```bash
sed -i 's/\r$//' scripts/lib/pg-hba-easywaf.sh
```

Либо переклонируйте репозиторий / выполните `git pull` после исправления `.gitattributes`, а на машине разработчика — `git add --renormalize . && git commit`. Репозиторий требует **LF** для всех `scripts/**/*.sh` (см. [README.md](../README.md)).

## PostgreSQL: `FATAL: Ident authentication failed for user "easywaf"`

Стандартный **pg_hba.conf** в некоторых сборках PostgreSQL сопоставляет **TCP** `127.0.0.1` с **`ident`/`peer`**, тогда как easy-waf использует **пароль** в `DATABASE_URL`. Побеждает первое совпавшее правило.

**Исправление (из корня репозитория, от root):**

```bash
sudo bash scripts/lib/pg-hba-easywaf.sh
```

Либо повторно запустите **`sudo bash scripts/install.sh`** (идемпотентно; вставляет `scram-sha-256` для пользователя `easywaf` / БД `easywaf` перед общими строками `host`, затем перечитывает конфигурацию PostgreSQL).

Затем: `sudo systemctl restart easy-waf-api easy-waf-acmed`.

## PostgreSQL: `password authentication failed for user "easywaf"` (SQLSTATE 28P01)

Пароль в **`DATABASE_URL`** в **`/etc/easy-waf/easy-waf.env`** не совпадает с **`ALTER USER easywaf`** в кластере (типично после ротации через **`scripts/lib/db-password.sh`** или ручной смены пароля).

**Исправление:** приведите учётные данные в соответствие — например, `sudo -u postgres psql -c "ALTER USER easywaf PASSWORD '…';"` и обновите **`DATABASE_URL`**, либо восстановите пароль из резервной копии. Полная очистка **конфигурации** **не** сбрасывает пароль роли в БД; см. [`docs/ADMIN-CLI.md`](ADMIN-CLI.md) — **`reset-appliance`** затрагивает только данные приложения / состояние HAProxy / UI-пользователей в таблицах PostgreSQL.

## `systemctl start easy-waf-api` падает сразу (exit 1)

1. Логи: `sudo journalctl -u easy-waf-api -n 50 --no-pager` (чаще всего отсутствует `DATABASE_URL`, лежит БД или испорчен env-файл).
2. **Адреса прослушивания:** задайте `EASY_WAF_LISTEN_HTTPS` в `/etc/easy-waf/easy-waf.env` (по умолчанию **8443**). Управляющий HTTP **выключен**, если `EASY_WAF_LISTEN_HTTP` не указывает на loopback или для не-loopback не задан `EASY_WAF_ALLOW_INSECURE_HTTP=1`. На некоторых хостах systemd-юнит **не должен** передавать литеральное `${VAR:-default}` в `ExecStart` — используйте штатный [`packaging/systemd/easy-waf-api.service`](../packaging/systemd/easy-waf-api.service) (только `ExecStart=/usr/sbin/easy-waf-api`; порты прослушивания и `EASY_WAF_STATE_DIR` берутся из `easy-waf.env`), затем `sudo systemctl daemon-reload`. Логи: `sudo journalctl -u easy-waf-api -b -o cat --no-pager | tail -30`.
3. Если в `DATABASE_URL` указан `127.0.0.1`, убедитесь, что PostgreSQL запущен: `systemctl status postgresql` (или `postgresql-*` в некоторых дистрибутивах). Чистая установка **`install.sh`** по умолчанию ставит локальный PostgreSQL; **`EASY_WAF_INSTALL_POSTGRES=0`** используйте только при внешней БД — тогда `postgresql.service` на хосте может отсутствовать.

## `go build`: `open dist/easy-waf-api: permission denied`

Каталог `dist/` или бинарники созданы от **root** (например, `sudo bash scripts/install.sh` собирал из исходников). Либо:

```bash
sudo chown -R "$(id -un):$(id -gn)" dist
go mod tidy && make build
```

Либо удалите и пересоберите: `sudo rm -rf dist && make build`. Свежий **`install.sh`** после сборки от root выполняет **`chown` для `dist/`** в пользу `SUDO_USER`, так что повторяться это не должно.

## fail2ban не установлен

В **Ubuntu 24.04** пакет **fail2ban** есть в стандартных репозиториях:

```bash
sudo apt-get update
sudo apt-get install -y fail2ban
sudo systemctl enable --now fail2ban
```

Повторно запустите **`sudo bash scripts/install.sh`**, чтобы установить **`easy-waf-hostd`** и удалить устаревшие drop-in'ы для сокета и sudoers.

## UI Fail2Ban: пустой список jail / bad gateway / permission denied

API **не** вызывает `fail2ban-client` от имени **`easy-waf`** и **не** использует `sudo` (`NoNewPrivileges=true`). Статус и разбан идут через **`easy-waf-hostd`**, который запускает **`fail2ban-client`** от root.

Проверьте (из корня репозитория на устройстве):

```bash
systemctl status easy-waf-hostd fail2ban
ls -la /run/easy-waf/hostd.sock
sudo fail2ban-client ping    # expect: pong
sudo fail2ban-client status
```

Если hostd не работает или сокет отсутствует, перезапустите после пересборки:

```bash
sudo systemctl restart easy-waf-hostd easy-waf-api
```

В старых установках могут оставаться **`/etc/sudoers.d/easy-waf-fail2ban`** или drop-in'ы сокета fail2ban; **`install.sh`** их удаляет. Прямой вызов `sudo -u easy-waf fail2ban-client` в текущих релизах **не** является поддерживаемой проверкой.

См. [FAIL2BAN.md](FAIL2BAN.md).

## System → Updates: лог обновления пуст, завис или «already in progress»

Живое обновление идёт через **`POST /api/v1/host/updates/upgrade/stream`** (NDJSON) с помощью **`easy-waf-hostd`**. Повторный запрос во время работы apt **подключается** к тому же логу (второй apt не запускается).

1. **Брокер запущен:** `systemctl status easy-waf-hostd` — сокет `/run/easy-waf/hostd.sock`.
2. **API пересобран и перезапущен** после изменений кода: `systemctl restart easy-waf-api` (UI встроен в бинарник).
3. **Блокировка dpkg:** `sudo fuser -v /var/lib/dpkg/lock-frontend` — перед ручным обновлением вывод должен быть пустым. Если блокировку держит `apt-daily` / `unattended-upgrades`, подождите или остановите их; в потоке появится строка об ожидании до 120 с (`DPkg::Lock::Timeout=120`).
4. **Зависшее «in progress»** (редко): если UI показывает выполняющееся обновление, а процесса apt уже нет, проверьте `GET /api/v1/host/updates/upgrade/status` и `sudo tail -f /var/lib/easy-waf/apt-upgrade.log`, и только если ни один процесс apt/dpkg не активен — перезапустите **`easy-waf-hostd`**.
5. **Жёстко обновите** страницу в браузере (Ctrl+Shift+R) после развёртывания нового `easy-waf-api`.

См. [HOST-API.md](HOST-API.md) (раздел про поток обновления).

## UI управления возвращает 403 / «management access denied»

- IP клиента вне **`management_allowed_cidrs`** (см. `GET /api/v1/settings` с разрешённого хоста либо поправьте БД/настройки).
- Аварийный вариант: **`easy-waf-admin reset-control-panel-access`** или **`EASY_WAF_BYPASS_MGMT_ACL=1`** — см. [ADMIN-CLI.md](ADMIN-CLI.md).

## HAProxy: `Permission denied` на `/var/lib/easy-waf/haproxy/haproxy.cfg`

HAProxy работает от пользователя `haproxy`; файлы easy-waf принадлежат `easy-waf:easy-waf` (режим `0750` на подкаталогах состояния). Пользователь `haproxy` должен входить в группу **`easy-waf`**, чтобы читать рабочий конфиг и деревья сертификатов.

**Быстрое исправление (из корня репозитория, от root):**

```bash
sudo bash scripts/fix-haproxy-easy-waf-dropin.sh
```

Этот скрипт:

1. Добавляет `haproxy` в группу `easy-waf` (`usermod -aG`), когда это нужно  
2. Пишет **`/etc/systemd/system/haproxy.service.d/easy-waf.conf`**, чтобы HAProxy загружал только сгенерированный **`haproxy.cfg`**  
3. Гарантирует наличие **`/run/haproxy/`** (stats socket; **`/etc/tmpfiles.d/easy-waf-haproxy.conf`** для перезагрузок)  
4. Выполняет **`systemctl daemon-reload`**

После скрипта: **`sudo systemctl restart haproxy`** (нужно, чтобы `haproxy` подхватил новую дополнительную группу).

**AppArmor:** в Ubuntu штатного профиля HAProxy обычно достаточно. Если видите `DENIED` в `/var/log/syslog`, выполните **`aa-status`** и при необходимости просмотрите **`/etc/apparmor.d/usr.sbin.haproxy`**.

**Полная переустановка** также применяет drop-in, если бинарник `haproxy` присутствует: **`sudo bash scripts/install.sh`**.

## HAProxy: `Binding … haproxy.cfg:5` для frontend `GLOBAL` / запуск завершается с кодом 1

Строка **5** в сгенерированном конфиге — обычно **`stats socket /run/haproxy/easy-waf-admin.sock`**. **`haproxy -c`** не создаёт этот Unix-сокет, поэтому проверка может пройти, а **`ExecStart`** — упасть, если **`/run/haproxy`** отсутствует, не принадлежит **`haproxy`** или остался устаревший **`easy-waf-admin.sock`**.

**Исправление:** запустите актуальный **`scripts/fix-haproxy-easy-waf-dropin.sh`** из репозитория (он пишет **`easy-waf.conf`** с **`ExecStartPre=+/bin/mkdir …`** — **`+`** выполняет эти шаги **от root**, поскольку штатный **`haproxy.service`** использует **`User=haproxy`**, а непривилегированный **`ExecStartPre`** не может сделать **`chown`** внутри **`/run`**, и удаляет устаревший **`50-easy-waf.conf`**), затем **`sudo systemctl daemon-reload && sudo systemctl restart haproxy`**.

Разовое ручное исправление:

```bash
sudo install -d -o haproxy -g haproxy -m 0755 /run/haproxy
sudo rm -f /run/haproxy/easy-waf-admin.sock
sudo systemctl restart haproxy
```

## HAProxy: `cannot bind UNIX socket (Permission denied)` (stats socket)

Путь stats socket по умолчанию — **`/run/haproxy/easy-waf-admin.sock`**. Если в **`global_settings_json`** остался устаревший **`…/haproxy/admin.sock`** внутри каталога состояния, **Apply** / **`apply-edge`** теперь автоматически переписывает его в **сгенерированном** `haproxy.cfg` на **`/run/haproxy/easy-waf-admin.sock`** (правка БД для этого конкретного устаревшего пути не требуется). Для любого другого нестандартного пути обновите настройки и выполните Apply:

```bash
curl --cacert /var/lib/easy-waf/secrets/management.crt -fsS -X PATCH \
  "https://127.0.0.1:8443/api/v1/settings" \
  -H "Authorization: Bearer $EASY_WAF_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"haproxy_stats_socket_path":"/run/haproxy/easy-waf-admin.sock"}'
```

Затем нажмите **Apply** в UI (или выполните **`easy-waf-admin apply-edge`**), чтобы перегенерировать **`haproxy.cfg`**.

## HAProxy: порты 80 / 443 недоступны (nftables)

HAProxy слушает **`*:80`** и **`*:443`**; если **`ss -tlnp`** показывает **`haproxy`**, а у клиентов таймаут, проверьте в **`sudo nft list ruleset`** наличие **`tcp dport { 80, 443 } accept`**.

**Исправление:** на устройстве из репозитория — **`sudo bash scripts/fix-nftables-edge.sh`**. Новые установки выполняют это автоматически через **`scripts/install.sh`**, если не задано **`EASY_WAF_NFT_EDGE=0`**.

## HAProxy: `bk_acme` / `127.0.0.1:8089` в состоянии DOWN (connection refused)

`fe_http` направляет `/.well-known/acme-challenge/` в **`bk_acme`**, где используется **`server … 127.0.0.1:8089 check`**. **`easy-waf-api`** должен быть запущен: по умолчанию он слушает этот loopback-адрес и отдаёт файлы токенов из webroot ACME (то же дерево, что использует **Lego** для HTTP-01). Если API остановлен или бинарник старее этого слушателя, HAProxy сообщает **connection refused** и **`backend bk_acme has no server available`**.

**Исправление:** `sudo systemctl start easy-waf-api` (или `restart`) после обновления. Чтобы отключить встроенный помощник (только если вы обслуживаете challenge иным способом), задайте **`EASY_WAF_ACME_INTERNAL_HTTP=0`** в **`/etc/easy-waf/easy-waf.env`** и перезапустите **`easy-waf-api`**. См. [ACME.md](ACME.md).

## Apply падает: «application … is unsafe to render» / «settings are unsafe to render»

`POST /api/v1/apply` заново проверяет каждое сохранённое значение, попадающее в
сгенерированную конфигурацию, и отказывает вместо того, чтобы записать файл,
который `haproxy -c` принял бы. В сообщении названы запись и поле. Так задумано:
проверка в обработчике API носит рекомендательный характер, потому что значение
может попасть в базу другим путём — восстановление из резервной копии, прямой
`UPDATE`, старая версия без валидатора.

Чаще всего встречается после обновления до 1.4.0:

- **`public_host must be lowercase`** или **`public_host contains invalid characters`** — переименуйте
  публичный хост приложения в нижний регистр без `_` (см.
  [ARCHITECTURE.md](ARCHITECTURE.md)) и выполните Apply снова.
- **`backend_tls_ca_file`** / путь к сертификату / путь в настройках — в значении
  есть пробел, перевод строки, `#`, кавычка или `$`. Принимаются абсолютные пути
  из символов `A-Z a-z 0-9 . _ ~ + @ : - /`; всё остальное могло бы добавить или
  изменить директиву в сгенерированном конфиге.
- **«both render as backend `bk_…`»** — два включённых приложения отображаются в
  один идентификатор HAProxy. В сообщении названы оба; измените один
  `public_host`.

Поправьте запись через UI или API и повторите Apply. Пока весь рендер не
завершится успешно, в HAProxy ничего не записывается, поэтому работающий edge
тем временем не затрагивается.

## HAProxy не перезагружает конфигурацию

1. `sudo haproxy -c -f /var/lib/easy-waf/haproxy/haproxy.cfg`
2. Сравните с последней рабочей ревизией в `/var/lib/easy-waf/revisions/`.
3. Используйте **Rollback** в UI или `restore.sh`.

## Не удаётся выпустить сертификат

- Проверьте, что DNS указывает на этот хост (для HTTP-01).
- Для DNS-01 проверьте учётные данные провайдера и доступность его API.
- Сначала используйте staging-режим.

## `install.sh` подвисает после «LAPI not ready» / поток строк `apt-get`

Старые инсталляторы в цикле повторяли **`apt-get -f install`**, хотя LAPI уже был поднят, потому что **`curl -f`** считал **401/405** ошибкой. Текущий **`scripts/lib/crowdsec-install.sh`**:

- Определяет LAPI через **`crowdsec_lapi_reachable`** (HTTP-статус или **`cscli lapi status`**).
- **Повторный запуск** (`crowdsec` уже установлен): восстановление **только средствами systemd**, максимум ~2 минуты, со строками лога **`waiting for LAPI (n/m)...`**.
- **Чистая установка**: один проход **`apt-get -f`**, затем то же восстановление через systemd.

Если и это не помогает: `systemctl status crowdsec`, `journalctl -u crowdsec -n 80`, `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/`, затем `sudo bash scripts/crowdsec-bootstrap-lapi.sh`.

## CrowdSec UI: 502 на decisions / при установке «LAPI decisions check failed»

Баунсеры LAPI аутентифицируются заголовком **`X-Api-Key: <key>`** ([документация CrowdSec](https://doc.crowdsec.net/docs/local_api/bouncers/)). Неверный заголовок → **403** → **502** в UI или ошибка установки, даже если `CROWDSEC_LAPI_KEY` в `easy-waf.env` корректен.

```bash
KEY=$(sudo grep '^CROWDSEC_LAPI_KEY=' /etc/easy-waf/easy-waf.env | cut -d= -f2-)
curl -s -o /dev/null -w '%{http_code}\n' -H "X-Api-Key: $KEY" 'http://127.0.0.1:8080/v1/decisions?limit=1'
# expect 200
```

После `git pull` + `make build`: переустановите бинарник API и выполните `sudo systemctl restart easy-waf-api` либо повторно запустите `sudo bash scripts/install.sh` (проверка при бутстрапе теперь использует `X-Api-Key`).

## Ошибки CrowdSec / SPOE

- Проверьте путь к файлу SPOE в `haproxy.cfg`.
- Убедитесь, что имя engine совпадает с секцией агента SPOE.
- Перезапустите баунсер после ротации ключа LAPI.

## Отказы AppArmor (Ubuntu)

- Выполните **`aa-status`** и просмотрите **`/var/log/syslog`** на предмет `apparmor="DENIED"`, связанных с **`haproxy`**.
- Штатного профиля Ubuntu **`/etc/apparmor.d/usr.sbin.haproxy`** обычно достаточно для чтения конфигов в **`/var/lib/easy-waf`**, когда **`haproxy`** состоит в группе **`easy-waf`**.
- **Не** отключайте AppArmor глобально; при нестандартных путях правьте профиль локально.

## Сбор диагностики (для поддержки)

1. **Из UI (быстро):** Dashboard → **Download diagnostics** — подтверждает, что сведения о системе и логи собираются с **маскированием секретов**, затем скачивает `.tar.gz`, собранный API (пользователь `easy-waf`). Часть проверок хоста без root может быть неполной; см. [DIAGNOSTICS.md](DIAGNOSTICS.md).
2. **Через API:** `POST /api/v1/diagnostics/bundle` (аутентифицированная сессия) — тот же архив, что и по кнопке; ответ приходит как `application/gzip` с `Content-Disposition: attachment`.
3. **Полный набор на устройстве (рекомендуется для поддержки):** запустите от **root**:
   - После установки: `sudo /usr/sbin/easy-waf-diagnostics`
   - Из репозитория: `sudo bash scripts/diagnostics.sh`
   - Вывод по умолчанию: `/tmp/easy-waf-diag-YYYYMMDD-HHMMSS.tar.gz`

Подробности, структура и что **не** включается: [DIAGNOSTICS.md](DIAGNOSTICS.md).
