#!/usr/bin/env bash
# DEPRECATED: Ubuntu 24.04 uses AppArmor, not SELinux.
# Retained for legacy AlmaLinux/RHEL installations only.
# On Ubuntu, HAProxy access is controlled via Unix group membership
# (haproxy in easy-waf group) and file permissions.
#
# SELinux file contexts so HAProxy (haproxy_t) can read easy-waf generated configs.
# Idempotent; run as root after install or restorecon.
# Env: EASY_WAF_STATE_DIR (default /var/lib/easy-waf)
set -euo pipefail

log() { echo "[easy-waf-selinux] $*"; }

if ! command -v semanage &>/dev/null; then
  log "semanage not found — skip (install policycoreutils-python-utils)"
  exit 0
fi

if ! command -v getenforce &>/dev/null || [[ "$(getenforce 2>/dev/null)" == "Disabled" ]]; then
  log "SELinux disabled or getenforce unavailable — skip"
  exit 0
fi

STATE="${EASY_WAF_STATE_DIR:-/var/lib/easy-waf}"

# HAProxy config + crt-list + maps → haproxy_var_lib_t (readable by haproxy_t)
semanage fcontext -a -t haproxy_var_lib_t "${STATE}/haproxy(/.*)?" 2>/dev/null \
  || semanage fcontext -m -t haproxy_var_lib_t "${STATE}/haproxy(/.*)?" 2>/dev/null \
  || true

# TLS bundles (certs dir) → haproxy_var_lib_t
semanage fcontext -a -t haproxy_var_lib_t "${STATE}/certs(/.*)?" 2>/dev/null \
  || semanage fcontext -m -t haproxy_var_lib_t "${STATE}/certs(/.*)?" 2>/dev/null \
  || true

# Stats socket lives under /run/haproxy (standard haproxy_var_run_t)
if [[ -d /run/haproxy ]]; then
  restorecon -Rv /run/haproxy 2>/dev/null || true
fi

# Apply contexts
if command -v restorecon &>/dev/null; then
  restorecon -Rv "${STATE}/haproxy" 2>/dev/null || true
  restorecon -Rv "${STATE}/certs" 2>/dev/null || true
fi

# Boolean: allow HAProxy to connect to arbitrary backend ports
if command -v setsebool &>/dev/null; then
  setsebool -P haproxy_connect_any 1 2>/dev/null || true
fi

log "SELinux contexts applied (haproxy_var_lib_t for ${STATE}/haproxy, ${STATE}/certs)"
