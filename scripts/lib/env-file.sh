#!/usr/bin/env bash

# Read one exact KEY=value entry without executing the env file as shell code.
easy_waf_read_env_value() {
  local file="$1" key="$2" line value found=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == "${key}="* ]] || continue
    value="${line#*=}"
    if [[ ${#value} -ge 2 ]]; then
      if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || \
         [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
        value="${value:1:${#value}-2}"
      fi
    fi
    found="$value"
  done <"$file"
  printf '%s' "$found"
}
