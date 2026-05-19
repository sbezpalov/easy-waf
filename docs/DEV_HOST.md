# Пилот-хост `waf-dev` (разработка и тест EasyWAF)

Короткий алиас **`waf-dev`** — целевой Linux-хост для пилота EasyWAF (Alma/RHEL‑семейство). Код правится локально (часто Windows), сборка и проверки — на этом хосте или в CI.

## 1. SSH: `~/.ssh/config`

На **Windows** (OpenSSH) и **Linux** добавьте блок (подставьте свой **`HostName`**: пилот **`192.0.2.10`**, DNS **`waf-dev.home.bezpalov.com`**) и пользователя:

```ssh-config
Host waf-dev
    HostName 192.0.2.10
    User youruser
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 30
```

Проверка:

```bash
ssh waf-dev 'uname -a && test -d ~/easy-waf && echo repo-ok'
```

**DNS (LAN):** `waf-dev.home.bezpalov.com` → `192.0.2.10` (если в `~/.ssh/config` указан IP, DNS не обязателен).

## 2. Cursor / VS Code — Remote SSH

1. Расширение **Remote - SSH**.
2. **Remote-SSH: Connect to Host…** → выберите **`waf-dev`**.
3. Откройте папку репозитория на хосте, например `~/easy-waf`.

В корне репозитория в **`.vscode/settings.json`** задано `remote.SSH.remotePlatform` для **`waf-dev`** → Linux, чтобы не спрашивал платформу при каждом подключении.

## 3. Git на пилоте

После подключения по SSH работайте с клоном на Linux как обычно (`git pull`, `make ci`, **`make verify`** — в т.ч. **ShellCheck** на `scripts/install.sh`). Конфликт локальных `go.mod` / неотслеживаемого `go.sum` с `git pull` — см. подсказки в ответе ассистента или `docs/DEPLOYMENT.md`.

## 4. Согласованность с CI

Эталон проверок — **AlmaLinux 10** (`make ci` на пилоте и **GitHub Actions**: контейнер `almalinux:10`) плюс зеркальный job на **Ubuntu 24.04** (`deb-family-ci` в `.github/workflows/ci.yml`). На Windows перед пушем имеет смысл прогнать те же шаги из **Git Bash / WSL** (см. `.cursor/rules/easy-waf-verify-after-edits.mdc`).
