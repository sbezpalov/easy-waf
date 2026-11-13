#!/usr/bin/env bash
# Execute the actual maintainer scheduling function without root or systemd.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
function_source="$(sed -n '/^restart_active_units() {$/,/^}$/p' "${ROOT}/packaging/deb/postinst")"
[[ -n "$function_source" ]] || { echo 'missing maintainer restart function' >&2; exit 1; }
eval "$function_source"
UNITS="$(sed -n 's/^UNITS="\(.*\)"$/\1/p' "${ROOT}/packaging/deb/postinst")"
export UNITS # Consumed by the actual function loaded above.

calls=()
warnings=0
mode=all
info() { warnings=$((warnings + 1)); }
systemctl() {
  calls+=("$*")
  case "$1" in
    is-active)
      case "$mode" in
        stopped) return 3 ;;
        api_only) [[ "$3" == easy-waf-api.service ]] ;;
        worker_only) [[ "$3" == easy-waf-apt.service ]] ;;
        *) return 0 ;;
      esac
      ;;
    restart)
      [[ "${3:-}" != easy-waf-hostd-restart.service || "$mode" != failed_queue ]]
      ;;
    *) return 0 ;;
  esac
}
has_call() {
  local item
  for item in "${calls[@]}"; do
    [[ "$item" != "$1" ]] || return 0
  done
  return 1
}
reject_call() {
  if has_call "$1"; then
    echo "unexpected command: $1" >&2
    exit 1
  fi
}
for mode in all stopped api_only worker_only failed_queue; do
  calls=()
  warnings=0
  restart_active_units
  if has_call 'restart easy-waf-hostd.service'; then
    echo "unsafe immediate broker restart in $mode" >&2; exit 1
  fi
  reject_call 'restart easy-waf-api.service'
  reject_call 'restart easy-waf-acmed.service'
  reject_call 'try-restart easy-waf-api.service'
  reject_call 'try-restart easy-waf-acmed.service'
  case "$mode" in
    all | failed_queue)
      has_call 'restart --no-block easy-waf-hostd-restart.service'
      has_call 'try-restart --no-block easy-waf-api.service'
      has_call 'try-restart --no-block easy-waf-acmed.service'
      if [[ "$mode" == failed_queue ]]; then
        [[ "$warnings" == 1 ]] # Warn, continue configuration, no unsafe fallback.
      else
        [[ "$warnings" == 0 ]]
      fi
      ;;
    stopped)
      [[ "${#calls[@]}" == 4 ]]
      ;;
    api_only)
      has_call 'try-restart --no-block easy-waf-api.service'
      reject_call 'restart --no-block easy-waf-hostd-restart.service'
      reject_call 'try-restart --no-block easy-waf-acmed.service'
      ;;
    worker_only)
      has_call 'restart --no-block easy-waf-hostd-restart.service'
      reject_call 'try-restart --no-block easy-waf-api.service'
      reject_call 'try-restart --no-block easy-waf-acmed.service'
      ;;
  esac
done

# Execute the source installer's real file-selection functions with mocked
# mutators, so the maintenance unit/policy cannot be accidentally omitted.
for function_name in install_systemd_units install_needrestart_policy; do
  function_source="$(sed -n "/^${function_name}() {$/,/^}$/p" "${ROOT}/scripts/install.sh")"
  [[ -n "$function_source" ]] || { echo "missing installer $function_name" >&2; exit 1; }
  eval "$function_source"
done
install() { calls+=("install $*"); }
log() { :; }
die() { echo "$*" >&2; exit 1; }
export EASY_WAF_SKIP_SYSTEMD=0
export EASY_WAF_PKG_INSTALLED=0
export SYSTEMD_SRC="${ROOT}/packaging/systemd"
export REPO_ROOT="$ROOT"
calls=()
install_systemd_units
install_needrestart_policy
has_call "install -m 0644 ${SYSTEMD_SRC}/easy-waf-hostd-restart.service /etc/systemd/system/easy-waf-hostd-restart.service"
has_call "install -m 0644 ${SYSTEMD_SRC}/easy-waf-apt.service /etc/systemd/system/easy-waf-apt.service"
has_call "install -m 0644 ${ROOT}/packaging/needrestart/easy-waf-hostd.conf /etc/needrestart/conf.d/easy-waf-hostd.conf"
reject_call 'enable --now easy-waf-hostd-restart.service'
calls=()
EASY_WAF_PKG_INSTALLED=1
install_systemd_units
install_needrestart_policy
[[ "${#calls[@]}" == 0 ]] # Package-owned files/conffiles are left to dpkg.

if command -v perl >/dev/null 2>&1; then
  perl - "${ROOT}/packaging/needrestart/easy-waf-hostd.conf" <<'PERL'
use strict;
use warnings;
our %nrconf = (override_rc => { qr(^existing\.service$) => 1 });
my $path = shift;
open my $file, '<', $path or die "open policy: $!";
my $code = do { local $/; <$file> };
eval $code;
die "invalid policy: $@" if $@;
for my $service ('easy-waf-hostd', 'easy-waf-hostd.service', 'easy-waf-apt', 'easy-waf-apt.service', 'easy-waf-api', 'easy-waf-api.service', 'easy-waf-acmed', 'easy-waf-acmed.service') {
    my @rules = grep { $service =~ $_ } keys %{$nrconf{override_rc}};
    die "missing managed-service override" unless @rules == 1 && $nrconf{override_rc}{$rules[0]} == 0;
}
for my $service ('haproxy.service', 'postgresql.service', 'easy-waf-hostd-restart.service', 'prefix-easy-waf-hostd.service') {
    die "policy affected $service" if grep { $service =~ $_ } keys %{$nrconf{override_rc}};
}
die "existing policy lost" unless keys(%{$nrconf{override_rc}}) == 2;
my @existing = grep { 'existing.service' =~ $_ } keys %{$nrconf{override_rc}};
die "existing policy changed" unless @existing == 1 && $nrconf{override_rc}{$existing[0]} == 1;
PERL
else
  echo 'SKIP needrestart policy evaluation (perl not in PATH)'
fi
echo 'package-safe broker restart: OK'
