#!/usr/bin/env bash
# Stage a complete verified release before touching the destination binaries.
# Authentication belongs to the caller; extraction is not an integrity check.

easy_waf_unpack_release() (
  local archive="${1:?}" destination="${2:?}" prefix="${3:-}" stage members member binary target restored
  local required=(easy-waf-hostd easy-waf-api easy-waf-acmed easy-waf-admin)
  local optional=(easy-wafd easy-waf-mcpd)
  local promoted=() retain_stage=0
  gzip -t "$archive" || return 1
  members="$(tar -tzf "$archive")" || return 1
  mkdir -p "$destination" || return 1
  stage="$(mktemp -d "${destination}/.release-stage.XXXXXX")" || return 1
  trap 'if (( ! retain_stage )); then rm -rf -- "$stage"; fi' EXIT
  for binary in "${required[@]}" "${optional[@]}"; do
    if ! member="$(printf '%s\n' "$members" | EASY_WAF_RELEASE_MEMBER_PREFIX="$prefix" awk -v b="$binary" '
      { normalized=$0; sub(/^\.\//,"",normalized)
        prefix=ENVIRON["EASY_WAF_RELEASE_MEMBER_PREFIX"]
        if (prefix!="") {
          if (index(normalized,prefix)!=1) next
          normalized=substr(normalized,length(prefix)+1)
        }
        if (normalized==b || normalized=="dist/" b) { count++; member=$0 } }
      END { if (count>1) exit 1; if (count==1) print member }
    ')"; then
      echo "[easy-waf-release] ambiguous archive member: $binary" >&2
      return 1
    fi
    if [[ -z "$member" ]]; then
      [[ "$binary" == easy-wafd || "$binary" == easy-waf-mcpd ]] && continue
      echo "[easy-waf-release] missing archive binary: $binary" >&2
      return 1
    fi
    # Stream only selected members to fixed private filenames. Never extract
    # archive-supplied paths, directory entries or links into the checkout.
    tar -xOzf "$archive" -- "$member" >"${stage}/${binary}" || return 1
    [[ -s "${stage}/${binary}" ]] || return 1
    chmod 0755 "${stage}/${binary}" || return 1
  done
  # Preserve the old set before renaming any staged binary into place.
  mkdir "$stage/previous" || return 1
  for binary in "${required[@]}" "${optional[@]}"; do
    [[ -f "${stage}/${binary}" ]] || continue
    target="$destination/$binary"
    if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
      echo "[easy-waf-release] unsafe binary destination: $binary" >&2
      return 1
    fi
    if [[ -f "$target" ]]; then
      cp -p -- "$target" "$stage/previous/$binary" || return 1
    fi
  done
  for binary in "${required[@]}" "${optional[@]}"; do
    [[ -f "${stage}/${binary}" ]] || continue
    if ! mv -f "$stage/$binary" "$destination/$binary"; then
      echo "[easy-waf-release] could not replace binary: $binary" >&2
      for restored in "${promoted[@]}"; do
        if [[ -f "$stage/previous/$restored" ]]; then
          mv -f "$stage/previous/$restored" "$destination/$restored" || retain_stage=1
        else
          rm -- "$destination/$restored" || retain_stage=1
        fi
      done
      if ((retain_stage)); then
        echo "[easy-waf-release] rollback incomplete; recovery files retained in $stage" >&2
      fi
      return 1
    fi
    promoted+=("$binary")
  done
)
