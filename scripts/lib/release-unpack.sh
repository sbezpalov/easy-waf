#!/usr/bin/env bash
# Stage a complete verified release before touching the destination binaries.
# Authentication belongs to the caller; extraction is not an integrity check.

easy_waf_unpack_release() (
  local archive="${1:?}" destination="${2:?}" stage members member binary
  local required=(easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin)
  local optional=(easy-wafd)
  gzip -t "$archive" || return 1
  members="$(tar -tzf "$archive")" || return 1
  mkdir -p "$destination" || return 1
  stage="$(mktemp -d "${destination}/.release-stage.XXXXXX")" || return 1
  trap 'rm -rf "$stage"' EXIT
  for binary in "${required[@]}" "${optional[@]}"; do
    if ! member="$(printf '%s\n' "$members" | awk -v b="$binary" '
      { normalized=$0; sub(/^\.\//,"",normalized)
        if (normalized==b || normalized=="dist/" b) { count++; member=$0 } }
      END { if (count>1) exit 1; if (count==1) print member }
    ')"; then
      echo "[easy-waf-release] ambiguous archive member: $binary" >&2
      return 1
    fi
    if [[ -z "$member" ]]; then
      [[ "$binary" == easy-wafd ]] && continue
      echo "[easy-waf-release] missing archive binary: $binary" >&2
      return 1
    fi
    # Stream only selected members to fixed private filenames. Never extract
    # archive-supplied paths, directory entries or links into the checkout.
    tar -xOzf "$archive" -- "$member" >"${stage}/${binary}" || return 1
    [[ -s "${stage}/${binary}" ]] || return 1
    chmod 0755 "${stage}/${binary}" || return 1
  done
  for binary in "${required[@]}" "${optional[@]}"; do
    [[ -f "${stage}/${binary}" ]] || continue
    if [[ -L "${destination}/${binary}" || -d "${destination}/${binary}" ]]; then
      echo "[easy-waf-release] unsafe binary destination: $binary" >&2
      return 1
    fi
  done
  for binary in "${required[@]}" "${optional[@]}"; do
    [[ -f "${stage}/${binary}" ]] || continue
    mv -f "${stage}/${binary}" "${destination}/${binary}" || return 1
  done
)
