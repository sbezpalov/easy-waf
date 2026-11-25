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
if [[ " $UNITS " == *' easy-waf-mcpd.service '* ]]; then
  echo 'MCP must stay out of the Debian first-install enable list' >&2
  exit 1
fi

calls=()
warnings=0
mode=all
info() { warnings=$((warnings + 1)); }
systemctl() {
  calls+=("$*")
  case "$1" in
    cat) [[ "$mode" != no_haproxy ]] ;;
    is-active)
      case "$mode" in
        stopped) return 3 ;;
        api_only) [[ "$3" == easy-waf-api.service ]] ;;
        worker_only) [[ "$3" == easy-waf-apt.service ]] ;;
        edge_only | failed_edge_queue) [[ "$3" == haproxy.service ]] ;;
        *) return 0 ;;
      esac
      ;;
    restart)
      [[ "${3:-}" != easy-waf-hostd-restart.service || "$mode" != failed_queue ]]
      ;;
    try-restart)
      [[ "${3:-}" != haproxy.service || "$mode" != failed_edge_queue ]]
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
  HAPROXY_DROPIN_MANAGED=0
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
      has_call 'try-restart --no-block easy-waf-mcpd.service'
      if [[ "$mode" == failed_queue ]]; then
        [[ "$warnings" == 1 ]] # Warn, continue configuration, no unsafe fallback.
      else
        [[ "$warnings" == 0 ]]
      fi
      ;;
    stopped)
      [[ "${#calls[@]}" == 5 ]]
      reject_call 'try-restart --no-block easy-waf-mcpd.service'
      ;;
    api_only)
      has_call 'try-restart --no-block easy-waf-api.service'
      reject_call 'restart --no-block easy-waf-hostd-restart.service'
      reject_call 'try-restart --no-block easy-waf-acmed.service'
      reject_call 'try-restart --no-block easy-waf-mcpd.service'
      ;;
    worker_only)
      has_call 'restart --no-block easy-waf-hostd-restart.service'
      reject_call 'try-restart --no-block easy-waf-api.service'
      reject_call 'try-restart --no-block easy-waf-acmed.service'
      reject_call 'try-restart --no-block easy-waf-mcpd.service'
      ;;
  esac
done

# An upgraded drop-in must take effect and recover an inherited missing stats
# listener. Only an active, managed edge is eligible; keep the operation queued.
export HAPROXY_DROPIN_MANAGED
for mode in all stopped edge_only failed_edge_queue; do
  for HAPROXY_DROPIN_MANAGED in 0 1; do
    calls=()
    warnings=0
    restart_active_units
    reject_call 'restart haproxy.service'
    reject_call 'try-restart haproxy.service'
    if [[ "$HAPROXY_DROPIN_MANAGED" == 1 && "$mode" != stopped ]]; then
      if ! has_call 'try-restart --no-block haproxy.service'; then
        echo "missing queued managed HAProxy restart: $mode" >&2; exit 1
      fi
      if [[ "$mode" == failed_edge_queue ]]; then [[ "$warnings" == 1 ]]; fi
      if [[ "$mode" == all ]]; then
        edge_index=-1
        api_index=-1
        for index in "${!calls[@]}"; do
          [[ "${calls[index]}" != 'try-restart --no-block haproxy.service' ]] || edge_index="$index"
          [[ "${calls[index]}" != 'try-restart --no-block easy-waf-api.service' ]] || api_index="$index"
        done
        ((edge_index >= 0 && api_index > edge_index))
      fi
    else
      reject_call 'try-restart --no-block haproxy.service'
      [[ "$warnings" == 0 ]]
    fi
  done
done

# Exercise the real ownership decision with all fixed OS paths redirected into
# an owned temporary tree. Only the install/systemctl leaves are replaced.
test_base="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
test_root="$(mktemp -d "${test_base}/easy-waf-package-haproxy.XXXXXX")"
cleanup() {
  [[ "$(dirname "$test_root")" == "$test_base" && "$(basename "$test_root")" == easy-waf-package-haproxy.* ]] || return 1
  rm -rf -- "$test_root"
}
trap cleanup EXIT
# Keep the replacement variable literal until the extracted function executes.
# shellcheck disable=SC2016
function_source="$(sed -n '/^install_haproxy_dropin() {$/,/^}$/p' "${ROOT}/packaging/deb/postinst" |
  sed 's|/usr/share/easy-waf|${TEST_PACKAGE_ROOT}/share|g; s|/etc/systemd/system|${TEST_PACKAGE_ROOT}/units|g')"
[[ -n "$function_source" ]] || { echo 'missing maintainer drop-in function' >&2; exit 1; }
eval "$function_source"
# Called by the extracted maintainer function.
# shellcheck disable=SC2317,SC2329
install() { cp -- "${@: -2:1}" "${@: -1}"; }
export TEST_PACKAGE_ROOT STATE_DIR
for fixture in missing_source no_haproxy custom owned fresh; do
  TEST_PACKAGE_ROOT="$test_root/$fixture"
  STATE_DIR="$TEST_PACKAGE_ROOT/state"
  mode="$fixture"
  HAPROXY_DROPIN_MANAGED=0
  mkdir -p "$TEST_PACKAGE_ROOT/share" "$TEST_PACKAGE_ROOT/units/haproxy.service.d" "$STATE_DIR/haproxy"
  printf 'existing config\n' >"$STATE_DIR/haproxy/haproxy.cfg"
  if [[ "$fixture" != missing_source ]]; then
    printf '# easy-waf fixture\nState=__EASY_WAF_STATE__\n' >"$TEST_PACKAGE_ROOT/share/haproxy-easy-waf-dropin.conf"
  fi
  dropin="$TEST_PACKAGE_ROOT/units/haproxy.service.d/easy-waf.conf"
  case "$fixture" in
    custom) printf 'operator-owned policy\n' >"$dropin" ;;
    owned) printf '# easy-waf old policy\n' >"$dropin" ;;
  esac
  install_haproxy_dropin
  case "$fixture" in
    owned | fresh)
      [[ "$HAPROXY_DROPIN_MANAGED" == 1 ]]
      grep -Fq "State=$STATE_DIR" "$dropin"
      ;;
    custom)
      [[ "$HAPROXY_DROPIN_MANAGED" == 0 && "$(cat "$dropin")" == 'operator-owned policy' ]]
      ;;
    *) [[ "$HAPROXY_DROPIN_MANAGED" == 0 && ! -e "$dropin" ]] ;;
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
export DIST_DIR="$test_root/dist"
mkdir -p "$DIST_DIR"
calls=()
install_systemd_units
install_needrestart_policy
has_call "install -m 0644 ${SYSTEMD_SRC}/easy-waf-hostd-restart.service /etc/systemd/system/easy-waf-hostd-restart.service"
has_call "install -m 0644 ${SYSTEMD_SRC}/easy-waf-apt.service /etc/systemd/system/easy-waf-apt.service"
has_call "install -m 0644 ${ROOT}/packaging/needrestart/easy-waf-hostd.conf /etc/needrestart/conf.d/easy-waf-hostd.conf"
reject_call 'enable --now easy-waf-hostd-restart.service'
mcp_install="install -m 0644 ${SYSTEMD_SRC}/easy-waf-mcpd.service /etc/systemd/system/easy-waf-mcpd.service"
reject_call "$mcp_install"
printf 'MCP binary fixture\n' >"$DIST_DIR/easy-waf-mcpd"
calls=()
install_systemd_units
has_call "$mcp_install"
for call in "${calls[@]}"; do
  if [[ "$call" == enable*easy-waf-mcpd* || "$call" == start*easy-waf-mcpd* ]]; then
    echo 'source installation activated the opt-in MCP service' >&2
    exit 1
  fi
done
calls=()
EASY_WAF_PKG_INSTALLED=1
install_systemd_units
install_needrestart_policy
[[ "${#calls[@]}" == 0 ]] # Package-owned files/conffiles are left to dpkg.

# The source unit's /etc filename is the target of an existing Wants link.
# Retiring that file must preserve the operator's previous enablement.
# shellcheck disable=SC2016 # The substituted paths are resolved in each fixture.
function_source="$(sed -n '/^retire_script_installed_units() {$/,/^}$/p' "${ROOT}/scripts/install.sh" |
  sed 's|/lib/systemd/system|${MCP_PACKAGE_UNIT_DIR}|g; s|/etc/systemd/system|${MCP_SOURCE_UNIT_DIR}|g')"
[[ -n "$function_source" ]]
eval "$function_source"
(
  export MCP_PACKAGE_UNIT_DIR="$test_root/mcp-packaged" MCP_SOURCE_UNIT_DIR="$test_root/mcp-source"
  mkdir -p "$MCP_PACKAGE_UNIT_DIR" "$MCP_SOURCE_UNIT_DIR"
  mcp_unit=easy-waf-mcpd.service
  printf 'packaged unit\n' >"$MCP_PACKAGE_UNIT_DIR/$mcp_unit"
  # Called indirectly by the installer function loaded with eval above.
  # shellcheck disable=SC2317,SC2329
  systemctl() {
    calls+=("$*")
    case "$1" in
      is-enabled)
        printf '%s\n' "$enabled"
        [[ "$enabled" != disabled ]]
        ;;
      is-active) [[ "$active" == yes ]] ;;
      reenable)
        [[ ! -e "$MCP_SOURCE_UNIT_DIR/$mcp_unit" ]] || return 92
        [[ "$failure" != reenable ]]
        ;;
      enable) [[ -f "$MCP_SOURCE_UNIT_DIR/$mcp_unit" ]] ;;
      daemon-reload | try-restart) return 0 ;;
      *) return 91 ;;
    esac
  }
  for scenario in enabled enabled-runtime disabled active reenable-failed; do
    enabled="$scenario" active=no failure=none
    case "$scenario" in
      active) enabled=disabled; active=yes ;;
      reenable-failed) enabled=enabled; failure=reenable ;;
    esac
    printf 'source unit\n' >"$MCP_SOURCE_UNIT_DIR/$mcp_unit"
    calls=()
    if [[ "$failure" == reenable ]]; then
      if (retire_script_installed_units) >"$test_root/mcp-rollback.log" 2>&1; then
        echo 'MCP unit migration did not report failed enablement transfer' >&2; exit 1
      fi
      grep -Fq 'restored the previous unit file' "$test_root/mcp-rollback.log"
      [[ -f "$MCP_SOURCE_UNIT_DIR/$mcp_unit" ]]
      continue
    fi
    retire_script_installed_units
    [[ ! -e "$MCP_SOURCE_UNIT_DIR/$mcp_unit" && -f "$MCP_SOURCE_UNIT_DIR/$mcp_unit.replaced-by-package" ]]
    case "$scenario" in
      enabled) [[ "${calls[1]}" == 'reenable --no-reload easy-waf-mcpd.service' ]] ;;
      enabled-runtime) [[ "${calls[1]}" == 'reenable --no-reload --runtime easy-waf-mcpd.service' ]] ;;
      disabled) [[ "${calls[*]}" == "is-active --quiet $mcp_unit daemon-reload" ]] ;;
      active) [[ "${calls[*]}" == "is-active --quiet $mcp_unit daemon-reload try-restart --no-block $mcp_unit" ]] ;;
    esac
  done
)

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
for my $service ('easy-waf-hostd', 'easy-waf-hostd.service', 'easy-waf-apt', 'easy-waf-apt.service', 'easy-waf-api', 'easy-waf-api.service', 'easy-waf-acmed', 'easy-waf-acmed.service', 'easy-waf-mcpd', 'easy-waf-mcpd.service') {
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
