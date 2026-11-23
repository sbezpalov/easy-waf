#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
export FIXTURE_DEB_TREE="$work/deb"
mkdir -p "$FIXTURE_DEB_TREE/usr/sbin" "$work/input/dist" "$work/bin"
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
for bin in easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin easy-wafd; do
  printf '%s\n' "$bin" >"$work/input/dist/$bin"
  if [[ "$bin" != easy-wafd ]]; then
    cp "$work/input/dist/$bin" "$FIXTURE_DEB_TREE/usr/sbin/$bin"
  fi
done
tar -czf "$work/fixture.tar.gz" -C "$work/input" .

check() {
  bash "$script_dir/verify-release-package.sh" fixture.deb "$work/fixture.tar.gz" arm64 1.6.1 \
    0123456789012345678901234567890123456789
}
reject() {
  local pattern="$1"
  if check >"$work/result" 2>&1; then
    printf 'test-release-package: accepted %s\n' "$pattern" >&2
    exit 1
  fi
  grep -Fq "$pattern" "$work/result" || { cat "$work/result" >&2; exit 1; }
}

check
FIXTURE_DEB_ARCH=amd64 reject 'wrong DEB architecture'
FIXTURE_DEB_VERSION=1.6.0 reject 'wrong DEB version'
FIXTURE_GO_ARCH=amd64 reject 'missing build setting GOARCH=arm64'
FIXTURE_MODIFIED=true reject 'missing build setting vcs.modified=false'
FIXTURE_REVISION=unrelated reject 'missing build setting vcs.revision='
printf 'different binary\n' >>"$FIXTURE_DEB_TREE/usr/sbin/easy-waf-api"
reject 'DEB executable differs from tarball: easy-waf-api'
echo 'test-release-package: PASS'
