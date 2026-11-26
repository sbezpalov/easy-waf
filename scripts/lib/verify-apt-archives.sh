#!/usr/bin/env bash
# Copyright 2026 Sergey Bezpalov
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# APT's version 1 hook sends one selected archive path per line.
found=0
while IFS= read -r archive; do
  package="$(dpkg-deb -f "$archive" Package)" || exit 1
  [[ "$package" == easy-waf ]] || continue
  hash="$(sha256sum <"$archive")"
  if (( found )) || [[ "${hash%% *}" != "${EASY_WAF_APT_EXPECTED_SHA:?}" ]]; then
    echo '[easy-waf] APT selected an Easy WAF archive that does not match the verified DEB' >&2
    exit 1
  fi
  found=1
done
if (( ! found )); then
  echo '[easy-waf] APT did not select the verified Easy WAF archive' >&2
  exit 1
fi
: >"${EASY_WAF_APT_GUARD_RECEIPT:?}"
