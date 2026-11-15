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
