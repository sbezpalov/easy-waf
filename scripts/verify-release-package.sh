#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if (( $# != 5 )); then
  echo 'Usage: bash verify-release-package.sh DEB TARBALL ARCH VERSION REVISION' >&2
  exit 2
fi
deb="$1"
archive="$2"
arch="$3"
version="$4"
revision="$5"
fail() { printf 'ERROR: release package %s: %s\n' "$arch" "$*" >&2; exit 1; }

[[ "$(dpkg-deb -f "$deb" Package)" == easy-waf ]] || fail 'wrong DEB package name'
[[ "$(dpkg-deb -f "$deb" Architecture)" == "$arch" ]] || fail 'wrong DEB architecture'
# Match EASY_WAF_DEB_VERSION in Makefile; keep the tag spelling for asset names.
[[ "$(dpkg-deb -f "$deb" Version)" == "${version//-/\~}" ]] || fail 'wrong DEB version'

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/deb" "$work/archive"
dpkg-deb -x "$deb" "$work/deb"
bins=(easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin easy-wafd easy-waf-mcpd)
units=(easy-waf-hostd.service easy-waf-api.service easy-waf-acmed.service easy-waf-mcpd.service
  easy-waf-apt.service easy-waf-hostd-restart.service easy-waf-backup.service easy-waf-backup.timer)
entries=()
for unit in "${units[@]}"; do
  entries+=("./packaging/systemd/$unit")
done
for bin in "${bins[@]}"; do
  entries+=("./dist/$bin")
done
tar -xzpf "$archive" -C "$work/archive" -- "${entries[@]}"

for unit in "${units[@]}"; do
  tar_unit="$work/archive/packaging/systemd/$unit"
  deb_unit="$work/deb/lib/systemd/system/$unit"
  [[ -f "$tar_unit" && ! -L "$tar_unit" && -f "$deb_unit" && ! -L "$deb_unit" ]] || fail "missing regular $unit"
  [[ "$(stat -c %a "$tar_unit")" == 644 ]] || fail "unexpected tarball unit mode for $unit"
  [[ "$(stat -c %a "$deb_unit")" == 644 ]] || fail "unexpected DEB unit mode for $unit"
  cmp -s "$tar_unit" "$deb_unit" || fail "$unit differs between DEB and tarball"
done

for legacy in usr/sbin/easy-wafd lib/systemd/system/easy-wafd.service; do
  [[ ! -e "$work/deb/$legacy" && ! -L "$work/deb/$legacy" ]] || fail "legacy $legacy included in DEB"
done

for bin in "${bins[@]}"; do
  packaged="$work/archive/dist/$bin"
  [[ -f "$packaged" && ! -L "$packaged" ]] || fail "missing regular tarball executable $bin"
  [[ "$(stat -c %a "$packaged")" == 755 ]] || fail "unexpected tarball executable mode for $bin"
  if [[ "$bin" != easy-wafd ]]; then
    installed="$work/deb/usr/sbin/$bin"
    [[ -f "$installed" && ! -L "$installed" ]] || fail "missing regular DEB executable $bin"
    [[ "$(stat -c %a "$installed")" == 755 ]] || fail "unexpected DEB executable mode for $bin"
    cmp -s "$packaged" "$installed" || fail "DEB executable differs from tarball: $bin"
  fi
  metadata="$(go version -m "$packaged")" || fail "could not read Go build information: $bin"
  for setting in "GOOS=linux" "GOARCH=$arch" "vcs.revision=$revision" 'vcs.modified=false'; do
    grep -Fxq $'\tbuild\t'"$setting" <<<"$metadata" || fail "$bin missing build setting $setting"
  done
done
printf 'Verified %s DEB and tarball for %s (%s)\n' "$arch" "$version" "$revision"
