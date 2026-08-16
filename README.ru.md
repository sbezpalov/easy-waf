# Easy Home WAF

[English](README.md) | **Русский**

[![CI](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/sbezpalov/easy-waf/actions/workflows/ci.yml)
[![Release](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml/badge.svg)](https://github.com/sbezpalov/easy-waf/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Self-hosted **WAF и защищённый reverse proxy** для публикации локальных сервисов
— Home Assistant, Frigate, Nextcloud, Node-RED, Grafana — через единый
защищённый HAProxy-edge, управляемый из локальной веб-панели, а не правкой
конфигов руками.

Он для тех, у кого дома или в небольшом офисе стоит хозяйство за NAT, кто хочет
открыть наружу два порта вместо десяти и предпочёл бы не становиться экспертом
по HAProxy ради корректных сертификатов, гео-фильтрации и блокировки ботов.

## Что он умеет

- **Один edge на всё.** У каждого приложения есть имя хоста, backend и профиль
  безопасности; конфигурация HAProxy генерируется, проверяется через
  `haproxy -c` и перечитывается — руками её никто не правит.
- **Слои защиты на каждое приложение**, переключаемые по хосту: rate limiting,
  базовые WAF-правила (SQLi/XSS/traversal), CrowdSec через SPOE, списки
  разрешённых и заблокированных IP с внешними фидами, GeoIP-фильтрация по
  странам, блокировка ботов и User-Agent, ограничения методов и путей, пути
  только для LAN. Пресеты — от *полной защиты* до *чистого reverse proxy*.
- **Сертификаты без церемоний.** ACME HTTP-01 и DNS-01 (Cloudflare, CloudNS,
  Route53, webhook), автоматическое продление, проверка TLS у HTTPS-бэкендов.
- **Управление хостом из той же панели:** сеть и nftables с **откатом по
  таймеру**, чтобы неудачное правило файрвола вернулось само, а не заперло вас
  снаружи; обновления системы с живым логом; сервисы, journal, локальные
  учётные записи.
- **Эксплуатационная безопасность:** каждый apply — это ревизия, к которой можно
  откатиться, привилегированные действия пишутся в аудит, `easy-waf-admin doctor`
  диагностирует appliance, а backup/restore покрывает базу, состояние и
  конфигурацию.

## Модель безопасности

Это appliance, который терминирует TLS на границе сети, поэтому дизайн исходит
из того, что часть компонентов будут атаковать и однажды один из них проиграет:

- `easy-waf-api` работает без привилегий (`NoNewPrivileges`, `ProtectSystem=strict`).
  Любая привилегированная операция идёт через **`easy-waf-hostd`** — root-брокер
  на unix-сокете, который проверяет пира через `SO_PEERCRED`, обрабатывает только
  разрешённые опкоды и **сам заново валидирует каждый аргумент**: в модели угроз
  скомпрометированный API учтён явно.
- **Пароля по умолчанию нет.** Первый оператор проходит enrollment по одноразовому
  CSPRNG-секрету, который читается только с локальной консоли.
- В сессии зашит `session_version`: смена пароля или выход отзывают все уже
  выданные токены.
- Значения, попадающие в сгенерированный конфиг, валидируются **повторно на этапе
  рендера** — потому что ошибка вида config injection даёт файл, который
  `haproxy -c` спокойно примет.
- Исходящие запросы (фиды блоклистов, CrowdSec LAPI) перепроверяют разрешённый IP
  в момент подключения — это закрывает DNS rebinding — и не следуют редиректам.
- Артефакты релиза проверяются по `SHA256SUMS` до того, как что-либо будет
  распаковано.

Сами меры и рассуждения за ними: [docs/SECURITY.md](docs/SECURITY.md).
Как сообщить об уязвимости: [SECURITY.md](SECURITY.md).

## Требования

- **Ubuntu 24.04 LTS** — единственная поддерживаемая платформа, и это осознанно
  (см. [CONTRIBUTING.md](CONTRIBUTING.md#what-this-project-is-and-is-not))
- root на appliance, systemd, nftables
- PostgreSQL — ставится автоматически либо подключается внешний
- 2 vCPU / 2 ГБ RAM — комфортный минимум, подробнее в
  [docs/VM-REQUIREMENTS.md](docs/VM-REQUIREMENTS.md)

## Установка

На чистой виртуальной машине с Ubuntu 24.04:

```bash
git clone https://github.com/sbezpalov/easy-waf.git
cd easy-waf
sudo bash scripts/install.sh
```

Установщик поставит HAProxy, PostgreSQL, CrowdSec + SPOA bouncer, fail2ban и
правила nftables, установит пакет `easy-waf` из соответствующего GitHub-релиза —
**с проверкой по `SHA256SUMS`**, и откажется ставить то, что проверку не прошло, —
затем запустит сервисы.

Дальше — вход. Пароля по умолчанию нет:

```bash
sudo easy-waf-admin print-enrollment      # одноразовый секрет, печатается локально
```

Откройте `https://<ip-appliance>:8443`, пройдите enrollment, добавьте первое
приложение. Полный разбор: [docs/QUICKSTART.md](docs/QUICKSTART.md).

Если PostgreSQL, nftables и CrowdSec уже настроены как надо, пакет ставится сам
по себе — сначала проверьте контрольную сумму:

```bash
sudo apt install ./easy-waf_<version>_amd64.deb
```

Обновление — это `apt install` более нового пакета; ваш
`/etc/easy-waf/easy-waf.env` объявлен conffile, поэтому он сохраняется, а не
перезаписывается. Почему упаковано именно так:
[ADR 0001](docs/adr/0001-packaging-and-installer.md).

## Документация

Документы в `docs/` ведутся на **английском** (канон); ниже — что в них искать.

**С чего начать**

| Документ | Что внутри |
|----------|------------|
| [QUICKSTART](docs/QUICKSTART.md) | Установка, первый вход, первое приложение |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | Компоненты, потоки данных, жизненный цикл конфигурации |
| [OPERATIONS](docs/OPERATIONS.md) | День второй: ручная проверка, переключатели, smoke-тест после обновления |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | Когда что-то не работает |

**Безопасность и слои защиты**

| Документ | Что внутри |
|----------|------------|
| [SECURITY](docs/SECURITY.md) | Hardening, модель привилегий, цепочка поставки, чеклист |
| [APPLICATION_SECURITY](docs/APPLICATION_SECURITY.md) · [SECURITY_PROFILES](docs/SECURITY_PROFILES.md) | Слои защиты приложения и пресеты |
| [CROWDSEC](docs/CROWDSEC.md) · [FAIL2BAN](docs/FAIL2BAN.md) | Поведенческая блокировка |
| [IPBL](docs/IPBL.md) · [GEOIP](docs/GEOIP.md) | Списки IP, внешние фиды, фильтрация по странам |

**Сертификаты, хост, эксплуатация**

| Документ | Что внутри |
|----------|------------|
| [ACME](docs/ACME.md) · [DNS01](docs/DNS01.md) · [DNS](docs/DNS.md) | Выпуск и продление |
| [HOST-API](docs/HOST-API.md) | Сеть, nftables, обновления, учётные записи |
| [BACKUP_RESTORE](docs/BACKUP_RESTORE.md) · [ADMIN-CLI](docs/ADMIN-CLI.md) | Резервные копии и аварийное восстановление |
| [MONITORING](docs/MONITORING.md) · [DIAGNOSTICS](docs/DIAGNOSTICS.md) | Метрики и диагностика |
| [DEPLOYMENT](docs/DEPLOYMENT.md) · [VM-REQUIREMENTS](docs/VM-REQUIREMENTS.md) | Развёртывание, OVF/OVA, сайзинг |
| [adr/](docs/adr/) | Архитектурные решения (ADR) |

## Как это устроено

```
cmd/easy-waf-api/     Management API + встроенный UI, рендер и apply HAProxy
cmd/easy-waf-acmed/   ACME-воркер (Lego)
cmd/easy-waf-hostd/   Root-брокер: разрешённые привилегированные операции на хосте
cmd/easy-waf-admin/   CLI: диагностика, enrollment, аварийное восстановление доступа
internal/             store (PostgreSQL), haproxy, api, auth, acme, ipbl, geoip, …
scripts/              install, upgrade, backup/restore, smoke-тест appliance
packaging/systemd/    Unit-файлы
docs/                 Руководства и ADR
```

PostgreSQL — единый source of truth. API рендерит из него конфигурацию HAProxy,
проверяет, применяет и хранит каждую ревизию для отката.

## Участие в проекте

Баг-репорты, исправления и правки документации приветствуются — начните с
[CONTRIBUTING.md](CONTRIBUTING.md): там написано, что входит в область проекта и
как прогнать те же проверки, что запускает CI.

**Никогда не сообщайте об уязвимости в публичном issue.** Используйте
[приватный канал](SECURITY.md).

## Статус

Автор использует проект в продакшене на домашней сети; описанные здесь интерфейсы
стабильны, а всё, что их ломает, проходит через `CHANGELOG.md` с примечанием об
обновлении. Это молодой проект, который ведёт один человек — прочитайте
[docs/SECURITY.md](docs/SECURITY.md), прежде чем ставить его перед тем, что вам
жалко потерять, и держите бэкапы (`scripts/backup.sh`).

## Лицензия

[Apache-2.0](LICENSE).
