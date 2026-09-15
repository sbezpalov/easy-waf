# Быстрый старт
[English](QUICKSTART.md) | **Русский** · канонический документ — английский; при расхождении верна английская версия. Переведено с 1.4.1.

**Целевая система:** Ubuntu 24.04 LTS (server), права **root** на аплаенсе.

**Версия поставки:** см. файл [`VERSION`](../VERSION) в корне репозитория (**1.4.1**); `scripts/install.sh` берёт её оттуда, чтобы скачать соответствующие артефакты из GitHub Releases (см. [`.github/workflows/release.yml`](../.github/workflows/release.yml)). Каждый артефакт проверяется по **`SHA256SUMS`** из того же релиза до того, как хоть что-то будет установлено, — см. [SECURITY.ru.md](SECURITY.ru.md#цепочка-поставок) и [ADR 0001](adr/0001-packaging-and-installer.md).

## Установка одной командой

Из корня репозитория на виртуальной машине:

```bash
sudo bash scripts/install.sh
```

**По умолчанию** (полный аплаенс, без дополнительных флагов) это:

1. Ставит **HAProxy, nftables**, **PostgreSQL**, **fail2ban** (запускает, если он установлен) и **CrowdSec + HAProxy SPOA bouncer** (бутстрап LAPI, ключи баунсера — в `easy-waf.env`).
2. Ставит **Debian-пакет `easy-waf`** той версии, что указана в `VERSION`: бинарники в `/usr/sbin`, юниты systemd в `/lib/systemd/system`, `/etc/easy-waf/easy-waf.env` — как **dpkg conffile**, чтобы последующие обновления сохраняли ваши правки.
3. Прописывает в env-файле **HTTPS `0.0.0.0:8443`** и **выключенный управляющий HTTP**; если старый env привязан к неактуальному LAN-адресу, установка переписывает его на `0.0.0.0` (для HTTP по-прежнему нужен loopback либо `EASY_WAF_ALLOW_INSECURE_HTTP=1`).
4. **Запускает** `easy-waf-hostd`, `easy-waf-api`, `easy-waf-acmed`, **crowdsec** и **crowdsec-spoa-bouncer**, если пакеты установились успешно.

### Только пакет, без подготовки окружения

Если PostgreSQL, nftables и CrowdSec уже приведены в тот вид, который вам нужен, поставьте
пакет отдельно и дальше действуйте сами:

```bash
curl -fLO https://github.com/sbezpalov/easy-waf/releases/download/v1.4.1/easy-waf_1.4.1_amd64.deb
curl -fLO https://github.com/sbezpalov/easy-waf/releases/download/v1.4.1/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS        # do not skip this
sudo apt install ./easy-waf_1.4.1_amd64.deb
```

Пакет ставится с включёнными юнитами, но **не запускает** их: задайте `DATABASE_URL` в
`/etc/easy-waf/easy-waf.env`, затем выполните `sudo systemctl start easy-waf-hostd
easy-waf-api easy-waf-acmed`.

### Нет сетевого доступа к GitHub

Если ни пакет, ни tarball не удаётся скачать и проверить, установщик
**останавливается**, а не собирает всё на самом аплаенсе: сборка оставила бы
Go, make и git установленными на машине, которая терминирует TLS. Либо укажите ему на
уже имеющиеся у вас артефакты (`sudo EASY_WAF_DIST_DIR=/path/to/dist bash
scripts/install.sh`), либо явно разрешите сборку:
`sudo EASY_WAF_BUILD_FROM_SOURCE=1 bash scripts/install.sh`.

**Только внешний PostgreSQL** (без локального пакета `postgresql`):

```bash
sudo EASY_WAF_INSTALL_POSTGRES=0 bash scripts/install.sh
```

Затем, до запуска сервисов, задайте `DATABASE_URL` в `/etc/easy-waf/easy-waf.env` (или отредактируйте файл и выполните `systemctl restart easy-waf-api easy-waf-acmed`).

**Не запускать** сервисы автоматически после установки (только разложить файлы):

```bash
sudo EASY_WAF_ENABLE_SYSTEMD_UNITS=0 bash scripts/install.sh
```

**CrowdSec** **включён по умолчанию** (`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`). См. [CROWDSEC.md](CROWDSEC.md).

Поэтапно / в изолированном контуре (только пакеты, LAPI позже):

```bash
sudo EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=0 bash scripts/install.sh
sudo bash scripts/crowdsec-bootstrap-lapi.sh   # when online
```

Полностью отказаться от CrowdSec: `sudo EASY_WAF_INSTALL_CROWDSEC=0 bash scripts/install.sh`

Необязательная привязка к **CrowdSec Console**: `EASY_WAF_CROWDSEC_CONSOLE_TOKEN=...` при запуске с **`EASY_WAF_CROWDSEC_AUTO_START_AFTER_INSTALL=1`**.

## После установки

- **UI (LAN):** по умолчанию **управляющий HTTP выключен**, а **`EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443`**. Откройте **`https://<LAN-IP>:8443`**. HTTP на loopback: **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`**. Устаревший открытый HTTP в LAN требует **`EASY_WAF_ALLOW_INSECURE_HTTP=1`** (не рекомендуется). Порт **8443** поднимается с **самоподписанным** сертификатом (`…/secrets/management.crt`); замените его через блок **Management TLS** в UI или запросом `PUT /api/v1/settings/management-tls`. **`install.sh`** настраивает **nftables**: **8000 и 8443/tcp** — только с **127.0.0.0/8** и **RFC1918** (при **`EASY_WAF_NFT_MGMT_LAN=1`**). **`/health`** живёт на HTTPS-прослушивателе (и на HTTP — только если вы его включили). ACME HTTP-01 остаётся на loopback **`127.0.0.1:8089`**.
- **Вход:** пароля по умолчанию нет. Под root на аплаенсе выполните **`easy-waf-admin print-enrollment`**, затем пройдите регистрацию в UI (или через `POST /api/v1/auth/enroll`), указав этот одноразовый секрет.

**Устаревший формат `EASY_WAF_LISTEN=...`:** задайте **`EASY_WAF_LISTEN_HTTP`** / **`EASY_WAF_LISTEN_HTTPS`** в `/etc/easy-waf/easy-waf.env` и удалите строку **`EASY_WAF_LISTEN`**. **Не** копируйте юниты из `packaging/systemd/` в `/etc/systemd/system/`: они перекрывают пакетные юниты в `/lib/systemd/system/`, и тогда обновление выглядит применённым, а systemd продолжает запускать старое определение. Затем выполните:

`sudo bash scripts/fix-nftables-edge.sh`

и `sudo systemctl daemon-reload && sudo systemctl restart easy-waf-api`.

**Только HTTPS на loopback (по умолчанию в интерактивном режиме):** `EASY_WAF_LISTEN_HTTP=off`, `EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`, **`EASY_WAF_NFT_MGMT_LAN=0`**. Для удалённого администрирования используйте проброс порта по SSH.

**Устаревший вариант — HTTP + HTTPS на loopback:** `EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`, `EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443`, **`EASY_WAF_NFT_MGMT_LAN=0`**.

**Без HTTPS:** `EASY_WAF_MANAGEMENT_HTTPS=0` плюс **`EASY_WAF_LISTEN_HTTP=127.0.0.1:8000`** (либо адрес не на loopback с **`EASY_WAF_ALLOW_INSECURE_HTTP=1`**). Если выключены оба прослушивателя, процесс не запустится.

## Интерактивный установщик

```bash
sudo bash scripts/install-interactive.sh
```

Режим по умолчанию — **`https_loopback`** (только HTTPS на `127.0.0.1:8443`). Выберите **`lan_rfc1918`**, чтобы получить HTTPS на `0.0.0.0:8443` вместе с управляющей политикой nftables, или явно укажите устаревший **`loopback`** — только если открытый HTTP на loopback всё ещё нужен. Переопределение в неинтерактивном режиме: `EASY_WAF_MGMT_MODE=https_loopback|lan_rfc1918|loopback`.

## Первое приложение

1. Войдите в UI.
2. **Applications → Add** → профиль (например, `home-assistant`).
3. Имя хоста, IP:порт бэкенда, при необходимости WebSocket.
4. **Certificates** → выпустите сертификат (сначала staging).
5. **Apply** → выполняется проверка `haproxy -c` и перезагрузка HAProxy.

## Пути

| Объект | По умолчанию |
|------|---------|
| Состояние | `/var/lib/easy-waf` |
| Конфигурация HAProxy | `/var/lib/easy-waf/haproxy/haproxy.cfg` |
| Env-файл | `/etc/easy-waf/easy-waf.env` |
| Файрвол хоста | `/etc/nftables/easy-waf.nft` |

Подробнее: [DEPLOYMENT.md](DEPLOYMENT.md), [OPERATIONS.md](OPERATIONS.md) (ручной `haproxy -c`, ревизии, `EASY_WAF_SKIP_*`), [TROUBLESHOOTING.ru.md](TROUBLESHOOTING.ru.md).

**Резервное копирование / восстановление:** [BACKUP_RESTORE.md](BACKUP_RESTORE.md) — `sudo bash scripts/backup.sh` (один `.tar.gz` с дампом БД, состоянием и `/etc/easy-waf`), `sudo bash scripts/restore.sh …`.
