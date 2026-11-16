#!/usr/bin/env bash
# Real tar and restore, fake DB/service/ownership leaves, private OS paths only.
set -euo pipefail
awk '$2 == "/etc/easy-waf" && $3 == "tmpfs" { found=1 } END { exit !found }' /proc/mounts || exit 90
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESTORE_SCRIPT="${1:-$SCRIPT_DIR/restore.sh}"
ROOT="$(mktemp -d)"
trap 'rm -rf "$ROOT"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
mkdir -p "$ROOT/bin" "$ROOT/source/backup/state" "$ROOT/source/backup/etc" "$ROOT/state"
state="$ROOT/source/backup/state"
mkdir -p "$state/haproxy" "$state/certs/nested" "$state/revisions" "$state/secrets"
printf 'fixture-config\n' >"$state/haproxy/haproxy.cfg"
printf 'fixture-pem\n' >"$state/certs/nested/test.pem"
printf 'fixture-secret\n' >"$state/secrets/private"
printf 'private-cert\n' >"$state/certs/private.pem"
printf 'fixture-dump\n' >"$ROOT/source/backup/easywaf.dump"
printf 'DATABASE_URL=postgres://fixture.invalid/never-connected\n' >"$ROOT/source/backup/etc/easy-waf.env"
chmod 0750 "$state" "$state/haproxy" "$state/certs" "$state/certs/nested" "$state/revisions"
chmod 0640 "$state/haproxy/haproxy.cfg" "$state/certs/nested/test.pem"
chmod 0700 "$state/secrets"
chmod 0600 "$state/secrets/private" "$state/certs/private.pem" "$ROOT/source/backup/etc/easy-waf.env"
tar -czf "$ROOT/archive.tar.gz" -C "$ROOT/source" backup
cat >"$ROOT/bin/pg_restore" <<'MOCK'
#!/usr/bin/env bash
set -eu
parent="$(dirname "$(dirname "${@: -1}")")"
[[ "$(stat -c %a "$parent")" == 700 ]] || exit 91
MOCK
for tool in systemctl chown; do printf '#!/bin/sh\nexit 0\n' >"$ROOT/bin/$tool"; done
chmod 0700 "$ROOT/bin/"*
mkdir -p "$ROOT/packaged scripts/lib" "$ROOT/operator commands"
restore_source="$(readlink -f "$RESTORE_SCRIPT")"
cp "$restore_source" "$ROOT/packaged scripts/restore.sh"
chmod 0755 "$ROOT/packaged scripts/restore.sh"
cp "$(dirname "$restore_source")/lib/env-file.sh" "$ROOT/packaged scripts/lib/"
ln -s '../packaged scripts/restore.sh' "$ROOT/operator commands/easy-waf-restore"
for entrypoint in "$RESTORE_SCRIPT" "$ROOT/operator commands/easy-waf-restore"; do
  restore_command=("$entrypoint")
  if [[ "$entrypoint" == "$RESTORE_SCRIPT" && $# == 0 ]]; then
    # Repository scripts are invoked with bash; nfpm makes the installed copy executable.
    restore_command=(bash "$entrypoint")
  fi
  if ! PATH="$ROOT/bin:$PATH" EASY_WAF_STATE_DIR="$ROOT/state" EASY_WAF_SKIP_APPLY=1 \
    "${restore_command[@]}" "$ROOT/archive.tar.gz" >"$ROOT/log" 2>&1; then
    cat "$ROOT/log" >&2
    fail 'restore failed'
  fi
  for dir in haproxy certs certs/nested revisions; do
    [[ "$(stat -c %a "$ROOT/state/$dir")" == 750 ]] || fail "restored $dir lost group traversal"
  done
  for file in haproxy/haproxy.cfg certs/nested/test.pem; do
    [[ "$(stat -c %a "$ROOT/state/$file")" == 640 ]] || fail "restored $file lost group readability"
  done
  [[ "$(stat -c %a "$ROOT/state/secrets")" == 700 ]] || fail 'private directory widened'
  for file in secrets/private certs/private.pem; do
    [[ "$(stat -c %a "$ROOT/state/$file")" == 600 ]] || fail 'private file widened'
  done
  [[ "$(stat -c %a /etc/easy-waf/easy-waf.env)" == 600 ]] || fail 'environment file widened'
done
echo 'OK: restore retains edge group access and private secret modes inside private staging'
