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
[[ "$(dpkg-deb -f "$deb" Version)" == "$version" ]] || fail 'wrong DEB version'

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/deb" "$work/archive"
dpkg-deb -x "$deb" "$work/deb"
bins=(easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin easy-wafd)
entries=()
for bin in "${bins[@]}"; do
  entries+=("./dist/$bin")
done
tar -xzf "$archive" -C "$work/archive" -- "${entries[@]}"

for bin in "${bins[@]}"; do
  packaged="$work/archive/dist/$bin"
  [[ -f "$packaged" && ! -L "$packaged" ]] || fail "missing regular tarball executable $bin"
  if [[ "$bin" != easy-wafd ]]; then
    installed="$work/deb/usr/sbin/$bin"
    [[ -f "$installed" && ! -L "$installed" ]] || fail "missing regular DEB executable $bin"
    cmp -s "$packaged" "$installed" || fail "DEB executable differs from tarball: $bin"
  fi
  metadata="$(go version -m "$packaged")" || fail "could not read Go build information: $bin"
  for setting in "GOOS=linux" "GOARCH=$arch" "vcs.revision=$revision" 'vcs.modified=false'; do
    grep -Fxq $'\tbuild\t'"$setting" <<<"$metadata" || fail "$bin missing build setting $setting"
  done
done
printf 'Verified %s DEB and tarball for %s (%s)\n' "$arch" "$version" "$revision"
