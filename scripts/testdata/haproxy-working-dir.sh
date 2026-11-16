#!/usr/bin/env bash
# Guard against running the OS-writing fixture outside its private mount layout.
set -euo pipefail
awk '$2 == "/etc/systemd/system" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts || exit 90
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
mkdir -p "$ROOT/bin" "$ROOT/private" "$ROOT/state/haproxy" "$ROOT/repo/dist"
chmod 0700 "$ROOT/private"
printf 'fixture-config\n' >"$ROOT/state/haproxy/haproxy.cfg"
printf 'fixture-env\n' >"$ROOT/env"
export HAPROXY_CWD_FIXTURE="$ROOT"
cat >"$ROOT/bin/id" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  -u) printf '0\n' ;;
  -nG) printf 'haproxy easy-waf\n' ;;
esac
MOCK
for name in chown aa-status; do printf '#!/bin/sh\nexit 0\n' >"$ROOT/bin/$name"; done
cat >"$ROOT/bin/systemctl" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$HAPROXY_CWD_FIXTURE/systemctl"
MOCK
cat >"$ROOT/bin/runuser" <<'MOCK'
#!/usr/bin/env bash
[[ "$1" == -u && "$2" == haproxy && "$3" == -- ]] || exit 91
shift 3
HAPROXY_CWD_UNPRIVILEGED=1 "$@"
MOCK
cat >/usr/sbin/haproxy <<'MOCK'
#!/usr/bin/env bash
if [[ "${HAPROXY_CWD_UNPRIVILEGED:-}" == 1 && "$(pwd)" != / ]]; then
  printf 'fixture: private caller cwd inaccessible after identity transition\n' >&2
  exit 92
fi
MOCK
cat >"$ROOT/repo/dist/easy-waf-admin" <<'MOCK'
#!/usr/bin/env bash
[[ "$(pwd)" == / && "$1" == apply-edge && "$2" == -env-file && "$3" == /* && "$4" == -state-dir && "$5" == /* ]] || exit 93
[[ -f "$3" && -f "$5/haproxy/haproxy.cfg" ]] || exit 94
[[ "$3" == "$HAPROXY_CWD_FIXTURE/env" && "$5" == "$HAPROXY_CWD_FIXTURE/state" ]] || exit 95
touch "$HAPROXY_CWD_FIXTURE/admin-called"
MOCK
chmod 0700 "$ROOT/bin/"* "$ROOT/repo/dist/easy-waf-admin" /usr/sbin/haproxy
export PATH="$ROOT/bin:$PATH"
cd "$ROOT/private"
export EASY_WAF_STATE_DIR=../state EASY_WAF_REPO_ROOT=../repo EASY_WAF_ENV_FILE=../env
if ! bash /repo/scripts/fix-haproxy-easy-waf-dropin.sh >"$ROOT/log" 2>&1; then
  cat "$ROOT/log" >&2
  echo 'FAIL: drop-in repair from private cwd failed' >&2
  exit 1
fi
grep -qxF 'User=haproxy' /etc/systemd/system/haproxy.service.d/easy-waf.conf || {
  echo 'FAIL: private caller cwd caused a root HAProxy fallback' >&2; exit 1;
}
[[ -f "$ROOT/admin-called" ]] || { echo 'FAIL: relative repo/env paths lost' >&2; exit 1; }
grep -qxF 'restart haproxy.service' "$ROOT/systemctl"
echo 'OK: private cwd and relative paths preserve unprivileged HAProxy repair'
