#!/usr/bin/env bash

# Read the last exact KEY=value line without evaluating its contents.
easy_waf_read_env_assignment() {
  local file="$1" key="$2" line found=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ "$line" == "${key}="* ]] || continue
    found="$line"
  done <"$file" || return
  printf '%s' "$found"
}

easy_waf_read_env_value() {
  local assignment value
  assignment="$(easy_waf_read_env_assignment "$@")" || return
  value="${assignment#*=}"
  if [[ ${#value} -ge 2 ]]; then
    if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || \
       [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf '%s' "$value"
}

# Import only explicitly requested keys. Missing entries preserve the invoking
# environment; explicit empty entries override it. Never evaluate file contents.
easy_waf_export_env_keys() {
  local file="$1" key value status
  shift
  [[ -f "$file" && -r "$file" ]] || return 1
  for key in "$@"; do
    [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]] || return 2
    if grep -q "^${key}=" "$file"; then
      value="$(easy_waf_read_env_value "$file" "$key")" || return
      export "$key=$value" || return
    else
      status=$?
      [[ "$status" == 1 ]] || return "$status"
    fi
  done
}

# easy-waf.env holds DATABASE_URL and API tokens. systemd reads it as root before
# dropping privileges (EnvironmentFile=), so no service account needs access, and
# group easy-waf must not get it: haproxy, the internet-facing process, is a
# member so that it can read generated configs and certificates.
easy_waf_secure_env_file() {
  chown root:root "$1"
  chmod 0600 "$1"
}
