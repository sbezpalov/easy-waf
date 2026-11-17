#!/usr/bin/env bash
# Exercise the destructive E2E driver's failure paths with all appliance
# operations replaced by shell functions. No root, database, or services needed.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(command mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
TEST_POSIX_MODES=0
if [[ "$(uname -s)" == Linux ]]; then TEST_POSIX_MODES=1; fi
export TEST_POSIX_MODES

id() { printf '0\n'; }
python3() {
  local dsn
  [[ "$1" == -I && "$2" == */lib/pg-archive.py && -d "$3" && "$4" == psql ]] || return 92
  dsn="$(cat)"
  [[ "$dsn" == "$TEST_EXPECTED_DSN" ]] || return 92
  shift 4
  psql --dbname=service=easy-waf-archive "$@"
}
psql() {
  local query="${!#}"
  [[ "$1" == --dbname=service=easy-waf-archive && -z "${E2E_UNUSED_SECRET+x}" ]] || return 92
  if [[ "$query" == *' AND certificate_id = '* && "$FAIL_AT" != wrong-db ]]; then
    printf '1\n'
    return
  fi
  printf '0\n'
}
systemctl() { :; }
chown() { :; }
sleep() { :; }
mktemp() {
  local path
  path="$(command mktemp "$@")"
  printf '%s\n' "$path" >"$TEST_CASE/temp-dir"
  printf '%s\n' "$path"
}
install() {
  if [[ "$1" == '-d' ]]; then
    mkdir -p -- "${@: -1}"
  else
    cp -- "${@: -2:1}" "${@: -1}"
  fi
}
bash() {
  case "$1" in
    */backup.sh)
      [[ "$(cat "$EASY_WAF_ENV_FILE")" == "DATABASE_URL=\"$TEST_EXPECTED_DSN\"" ]] || return 93
      printf '%s\n' "$EASY_WAF_ENV_FILE" >"$TEST_CASE/backup-env-path"
      printf 'recovery archive\n' >"$2"
      printf '%s\n' "$2" >"$TEST_CASE/backup-path"
      ;;
    */restore.sh)
      [[ "$FAIL_AT" != restore ]] || return 43
      mkdir -p "$EASY_WAF_STATE_DIR/haproxy"
      printf '10.77.88.99\n' >"$EASY_WAF_STATE_DIR/haproxy/haproxy.cfg"
      ;;
    *) "$BASH" "$@" ;;
  esac
}
curl() {
  local url='' output='' data=0 method=GET payload='' header='' header_file child_env
  child_env="$(command env)"
  if [[ "$child_env" =~ (^|$'\n')(EASY_WAF_)?E2E_(USERNAME|PASSWORD|TOTP_CODE)= ]]; then return 94; fi
  while (($#)); do
    case "$1" in
      -o) output="$2"; shift 2 ;;
      -X) method="$2"; shift 2 ;;
      --data-binary) data=1; shift 2 ;;
      -H)
        case "$2" in
          @*)
            header_file="${2#@}"
            [[ -f "$header_file" ]] || return 94
            if [[ "$TEST_POSIX_MODES" == 1 && "$(stat -c %a "$header_file")" != 600 ]]; then return 94; fi
            header="$(<"$header_file")"
            ;;
          Authorization:*) return 94 ;;
        esac
        shift 2
        ;;
      -w|--cacert) shift 2 ;;
      http*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  if [[ "$data" == 1 ]]; then
    payload="$(command cat)"
  fi
  if [[ "$url" == */auth/login ]]; then
    [[ -z "$header" ]] || return 94
  elif [[ "$url" == */auth/confirm || "$method" == GET ]]; then
    [[ "$header" == 'Authorization: Bearer fixture-session-token' ]] || return 94
  else
    [[ "$header" == 'Authorization: Bearer fixture-step-up-token' ]] || return 94
  fi
  case "$url" in
    */auth/login)
      [[ "$payload" == '{"username":"test","password":"test","totp_code":"123456"}' ]] || return 94
      printf '{"token":"fixture-session-token"}\n' >"$output"
      printf '200'
      ;;
    */auth/confirm)
      [[ "$payload" == '{"password":"test"}' ]] || return 94
      if [[ "$FAIL_AT" == auth-denied ]]; then
        printf '{"error":"fixture-sensitive-auth-response"}\n' >"$output"
        printf '401'
        return
      fi
      printf '{"token":"fixture-step-up-token"}\n' >"$output"
      printf '200'
      ;;
    */certificates)
      printf '%s' "$payload" >"$TEST_CASE/certificate.json"
      ;;
    */applications)
      if [[ "$method" == POST ]]; then
        printf '%s' "$payload" >"$TEST_CASE/application.json"
      else
        [[ "$FAIL_AT" != verify ]] || return 44
        printf '[{"id":"e2e-backup-restore-app","backend_host":"10.77.88.99"}]'
      fi
      ;;
    */apply)
      if [[ "$payload" == *e2e-cleanup* && "$FAIL_AT" == cleanup ]]; then
        return 45
      fi
      ;;
  esac
}
export -f id python3 psql systemctl chown sleep mktemp install bash curl

for destination in default explicit; do
  for FAIL_AT in none auth-denied wrong-db reset restore verify cleanup; do
    TEST_CASE="$TEST_ROOT/$destination-$FAIL_AT"
    mkdir -p "$TEST_CASE"
    export TEST_CASE FAIL_AT
    export TMPDIR="$TEST_CASE"
    export EASY_WAF_STATE_DIR="$TEST_CASE/state with spaces"
    export EASY_WAF_ENV_FILE="$TEST_CASE/appliance.env"
    export EASY_WAF_E2E_CERT_PEM="$TEST_CASE/source.pem"
    export EASY_WAF_ADMIN_BIN="$TEST_CASE/admin"
    export TEST_EXPECTED_DSN="postgres://fixture:literal-\$not_expanded@fixture.invalid/db"
    export not_expanded='must-stay-literal'
    unset E2E_UNUSED_SECRET
    printf 'UNUSED=%s\nE2E_UNUSED_SECRET=fixture-only\nDATABASE_URL="%s"\nSTATE="%s"\n' \
      "\$(touch \"$TEST_CASE/env-executed\")" "$TEST_EXPECTED_DSN" "$TEST_CASE/incorrect-state" >"$EASY_WAF_ENV_FILE"
    printf 'test certificate\n' >"$EASY_WAF_E2E_CERT_PEM"
    cat >"$EASY_WAF_ADMIN_BIN" <<'MOCK'
#!/usr/bin/env bash
set -eu
[[ "$1" == factory-reset && "$2" == -i-am-sure=true && "$3" == "-state-dir=$EASY_WAF_STATE_DIR" &&
   "$4" == -env-file && "$5" == "$(<"$TEST_CASE/backup-env-path")" ]] || exit 99
[[ "$FAIL_AT" != reset ]] || exit 42
MOCK
    chmod +x "$EASY_WAF_ADMIN_BIN"
    unset EASY_WAF_E2E_BACKUP_PATH
    if [[ "$destination" == explicit ]]; then
      export EASY_WAF_E2E_BACKUP_PATH="$TEST_CASE/custom-backup.tar.gz"
    fi
    export RUN_BACKUP_RESTORE_E2E=1 EASY_WAF_E2E_USERNAME=test EASY_WAF_E2E_PASSWORD=test EASY_WAF_E2E_TOTP_CODE=123456
    export E2E_USERNAME=inherited E2E_PASSWORD=inherited E2E_TOTP_CODE=inherited
    status=0
    "$BASH" "$SCRIPT_DIR/test-backup-restore.sh" >"$TEST_CASE/output" 2>&1 || status=$?
    [[ ! -e "$TEST_CASE/env-executed" ]] || { echo 'FAIL: backup driver executed env file'; exit 1; }
    if [[ "$FAIL_AT" == auth-denied ]]; then
      [[ "$status" == 1 && ! -e "$TEST_CASE/backup-path" && ! -d "$(<"$TEST_CASE/temp-dir")" ]]
      grep -Fq 'request to /api/v1/auth/confirm failed (HTTP 401)' "$TEST_CASE/output"
      if grep -Fq 'fixture-sensitive-auth-response' "$TEST_CASE/output"; then exit 1; fi
      echo "PASS: $destination backup, auth failure discards private response"
      continue
    fi
    if [[ "$FAIL_AT" == wrong-db ]]; then
      [[ "$status" == 1 && ! -e "$TEST_CASE/backup-path" ]]
      grep -Fq 'panel application is absent from the selected database' "$TEST_CASE/output"
      echo "PASS: $destination backup, rejected mismatched database before reset"
      continue
    fi
    backup="$(<"$TEST_CASE/backup-path")"
    temp_dir="$(<"$TEST_CASE/temp-dir")"
    if [[ "$FAIL_AT" == none ]]; then
      [[ "$status" == 0 && ! -e "$backup" && ! -d "$temp_dir" ]] || {
        cat "$TEST_CASE/output"; echo 'FAIL: successful run did not clean up'; exit 1;
      }
    else
      case "$FAIL_AT" in
        reset) expected_status=42 ;;
        restore) expected_status=43 ;;
        verify) expected_status=44 ;;
        cleanup) expected_status=45 ;;
      esac
      [[ "$status" == "$expected_status" && -s "$backup" ]] || {
        cat "$TEST_CASE/output"; echo 'FAIL: failed run lost recovery archive'; exit 1;
      }
      grep -Fq "recovery backup retained: $backup" "$TEST_CASE/output"
      [[ ! -d "$temp_dir/auth" ]]
      [[ ! -d "$temp_dir/pg-client" ]]
    fi
    expected_cert="$(printf '{"id":"e2e-backup-restore-cert","primary_domain":"backup-restore-e2e.example.local","mode":"self-signed","pem_crt_path":"%s/certs/_e2e/e2e-bundle.pem"}' "$EASY_WAF_STATE_DIR")"
    [[ "$(<"$TEST_CASE/certificate.json")" == "$expected_cert" ]]
    [[ "$(<"$TEST_CASE/application.json")" == '{"id":"e2e-backup-restore-app","name":"E2E Backup","public_host":"backup-restore-e2e.example.local","backend_host":"10.77.88.99","backend_port":8080,"profile":"balanced","certificate_id":"e2e-backup-restore-cert","enabled":true}' ]]
    # Default recovery directories deliberately survive a failed child process;
    # remove only the exact fixture directory recorded by our mktemp mock.
    command rm -rf -- "$temp_dir"
    echo "PASS: $destination backup, $FAIL_AT"
  done
done
