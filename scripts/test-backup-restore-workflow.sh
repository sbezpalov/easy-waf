#!/usr/bin/env bash
# Exercise the destructive E2E driver's failure paths with all appliance
# operations replaced by shell functions. No root, database, or services needed.
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

id() { printf '0\n'; }
psql() { printf '0\n'; }
systemctl() { :; }
chown() { :; }
sleep() { :; }
env() {
  # The driver invokes factory-reset via env DATABASE_URL=... admin ... .
  # Intercept it here so no executable or host operation can escape the fixture.
  [[ "$1" == DATABASE_URL=* && "$2" == "$EASY_WAF_ADMIN_BIN" && "$3" == factory-reset ]] || return 99
  [[ "$FAIL_AT" != reset ]] || return 42
}
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
  local url='' output='' data=0 method=GET payload=''
  while (($#)); do
    case "$1" in
      -o) output="$2"; shift 2 ;;
      -X) method="$2"; shift 2 ;;
      --data-binary) data=1; shift 2 ;;
      -H|-w|--cacert) shift 2 ;;
      http*) url="$1"; shift ;;
      *) shift ;;
    esac
  done
  if [[ "$data" == 1 ]]; then
    payload="$(command cat)"
  fi
  case "$url" in
    */auth/login|*/auth/confirm)
      printf '{"token":"test-session"}\n' >"$output"
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
export -f id psql systemctl chown sleep env mktemp install bash curl

for destination in default explicit; do
  for FAIL_AT in none reset restore verify cleanup; do
    TEST_CASE="$TEST_ROOT/$destination-$FAIL_AT"
    mkdir -p "$TEST_CASE"
    export TEST_CASE FAIL_AT
    export TMPDIR="$TEST_CASE"
    export EASY_WAF_STATE_DIR="$TEST_CASE/state with spaces"
    export EASY_WAF_ENV_FILE="$TEST_CASE/appliance.env"
    export EASY_WAF_E2E_CERT_PEM="$TEST_CASE/source.pem"
    export EASY_WAF_ADMIN_BIN="$TEST_CASE/admin"
    printf 'DATABASE_URL=test-only\n' >"$EASY_WAF_ENV_FILE"
    printf 'test certificate\n' >"$EASY_WAF_E2E_CERT_PEM"
    printf '#!/bin/bash\n# Mock executable; factory-reset is intercepted by env().\n' >"$EASY_WAF_ADMIN_BIN"
    chmod +x "$EASY_WAF_ADMIN_BIN"
    unset EASY_WAF_E2E_BACKUP_PATH
    if [[ "$destination" == explicit ]]; then
      export EASY_WAF_E2E_BACKUP_PATH="$TEST_CASE/custom-backup.tar.gz"
    fi
    export RUN_BACKUP_RESTORE_E2E=1 EASY_WAF_E2E_USERNAME=test EASY_WAF_E2E_PASSWORD=test
    status=0
    "$BASH" "$SCRIPT_DIR/test-backup-restore.sh" >"$TEST_CASE/output" 2>&1 || status=$?
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
      [[ ! -f "$temp_dir/auth-response" ]]
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
