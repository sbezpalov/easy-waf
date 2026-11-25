#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
umask 022

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export FIXTURE_DEB_TREE="$work/deb"
mkdir -p "$FIXTURE_DEB_TREE/usr/sbin" "$work/input/dist" "$work/bin"
mkdir -p "$FIXTURE_DEB_TREE/lib/systemd/system" "$work/input/packaging/systemd"
export PATH="$work/bin:$PATH"
export FIXTURE_DEB_ARCH=arm64 FIXTURE_DEB_VERSION=1.6.1
export FIXTURE_GO_ARCH=arm64 FIXTURE_REVISION=0123456789012345678901234567890123456789 FIXTURE_MODIFIED=false
cat >"$work/bin/dpkg-deb" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
case "$1:$2:${3:-}" in
  -f:fixture.deb:Package) echo easy-waf ;;
  -f:fixture.deb:Version) echo "$FIXTURE_DEB_VERSION" ;;
  -f:fixture.deb:Architecture) echo "$FIXTURE_DEB_ARCH" ;;
  -x:fixture.deb:*) cp -R "$FIXTURE_DEB_TREE"/. "$3/" ;;
  *) exit 90 ;;
esac
MOCK
cat >"$work/bin/go" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == version && "$2" == -m ]]
printf '\tbuild\tGOOS=linux\n\tbuild\tGOARCH=%s\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.modified=%s\n' \
  "$FIXTURE_GO_ARCH" "$FIXTURE_REVISION" "$FIXTURE_MODIFIED"
MOCK
chmod +x "$work/bin/"*
for bin in easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin easy-wafd easy-waf-mcpd; do
  printf '%s\n' "$bin" >"$work/input/dist/$bin"
  chmod 0755 "$work/input/dist/$bin"
  if [[ "$bin" != easy-wafd ]]; then
    cp "$work/input/dist/$bin" "$FIXTURE_DEB_TREE/usr/sbin/$bin"
  fi
done
for unit in easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service easy-waf-mcpd.service \
  easy-waf-apt.service easy-waf-hostd-restart.service easy-waf-backup.service easy-waf-backup.timer; do
  install -m 0644 "$script_dir/../packaging/systemd/$unit" "$work/input/packaging/systemd/"
  install -m 0644 "$work/input/packaging/systemd/$unit" "$FIXTURE_DEB_TREE/lib/systemd/system/"
done
pack_fixture() { tar -czf "$work/fixture.tar.gz" -C "$work/input" .; }
pack_fixture
guide="$FIXTURE_DEB_TREE/usr/share/doc/easy-waf/BACKUP_RESTORE.md"
install -D -m 0644 "$script_dir/../docs/BACKUP_RESTORE.md" "$guide"

check() {
  bash "$script_dir/verify-release-package.sh" fixture.deb "$work/fixture.tar.gz" arm64 "${1:-1.6.1}" \
    0123456789012345678901234567890123456789
}
reject() {
  local pattern="$1"
  shift
  if check "$@" >"$work/result" 2>&1; then
    printf 'test-release-package: accepted %s\n' "$pattern" >&2
    exit 1
  fi
  grep -Fq "$pattern" "$work/result" || { cat "$work/result" >&2; exit 1; }
}

check
printf 'stale guide\n' >"$guide"
reject 'packaged recovery guide differs from the source'
install -m 0644 "$script_dir/../docs/BACKUP_RESTORE.md" "$guide"
FIXTURE_DEB_VERSION=1.7.0~rc.1 check 1.7.0-rc.1
FIXTURE_DEB_VERSION=1.7.0~rc.1+build.2 check 1.7.0-rc.1+build.2
FIXTURE_DEB_VERSION=1.7.0-rc.1 reject 'wrong DEB version' 1.7.0-rc.1
FIXTURE_DEB_VERSION=1.7.0~rc.2 reject 'wrong DEB version' 1.7.0-rc.1
FIXTURE_DEB_ARCH=amd64 reject 'wrong DEB architecture'
FIXTURE_DEB_VERSION=1.6.0 reject 'wrong DEB version'
FIXTURE_GO_ARCH=amd64 reject 'missing build setting GOARCH=arm64'
FIXTURE_MODIFIED=true reject 'missing build setting vcs.modified=false'
FIXTURE_REVISION=unrelated reject 'missing build setting vcs.revision='
chmod 0644 "$FIXTURE_DEB_TREE/usr/sbin/easy-waf-mcpd"
reject 'unexpected DEB executable mode for easy-waf-mcpd'
chmod 0755 "$FIXTURE_DEB_TREE/usr/sbin/easy-waf-mcpd"
chmod 0644 "$work/input/dist/easy-waf-mcpd"
pack_fixture
reject 'unexpected tarball executable mode for easy-waf-mcpd'
chmod 0755 "$work/input/dist/easy-waf-mcpd"
chmod 0755 "$work/input/packaging/systemd/easy-waf-mcpd.service"
pack_fixture
reject 'unexpected tarball unit mode for easy-waf-mcpd.service'
chmod 0644 "$work/input/packaging/systemd/easy-waf-mcpd.service"
chmod 0600 "$FIXTURE_DEB_TREE/lib/systemd/system/easy-waf-backup.timer"
pack_fixture
reject 'unexpected DEB unit mode for easy-waf-backup.timer'
chmod 0644 "$FIXTURE_DEB_TREE/lib/systemd/system/easy-waf-backup.timer"
mv "$work/input/packaging/systemd/easy-waf-backup.timer" "$work/timer"
pack_fixture
reject 'easy-waf-backup.timer'
mv "$work/timer" "$work/input/packaging/systemd/easy-waf-backup.timer"
pack_fixture
printf 'legacy alias\n' >"$FIXTURE_DEB_TREE/lib/systemd/system/easy-wafd.service"
reject 'legacy lib/systemd/system/easy-wafd.service included in DEB'
rm "$FIXTURE_DEB_TREE/lib/systemd/system/easy-wafd.service"
printf 'different unit\n' >>"$FIXTURE_DEB_TREE/lib/systemd/system/easy-waf-mcpd.service"
reject 'easy-waf-mcpd.service differs between DEB and tarball'
cp "$work/input/packaging/systemd/easy-waf-mcpd.service" "$FIXTURE_DEB_TREE/lib/systemd/system/"
printf 'different binary\n' >>"$FIXTURE_DEB_TREE/usr/sbin/easy-waf-api"
reject 'DEB executable differs from tarball: easy-waf-api'
echo 'test-release-package: PASS'
