#!/usr/bin/env bash
# nftables helpers for Easy Home WAF (Ubuntu appliance).
# Sourced by install.sh — do not run standalone.

EASY_WAF_NFT_RULES="/etc/nftables/easy-waf.nft"
EASY_WAF_NFT_GUARD="/etc/nftables/easy-waf-guard.nft"
EASY_WAF_NFT_CONF="/etc/nftables.conf"

easy_waf_nft_private_nets() {
  local extra="${1:-}"
  echo "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
  if [[ -n "$extra" ]]; then
    echo ", $extra"
  fi
}

# Render managed ruleset to EASY_WAF_NFT_RULES (root).
easy_waf_nft_write_ruleset() {
  local mgmt_lan="${1:-1}"
  local mgmt_ports="${2:-8000 8443}"
  local edge="${3:-1}"
  local extra_cidr="${4:-}"

  local port_list=""
  local p
  for p in $mgmt_ports; do
    [[ -n "$port_list" ]] && port_list+=", "
    port_list+="$p"
  done

  local mgmt_block=""
  if [[ "$mgmt_lan" == "1" ]]; then
    local nets
    nets="$(easy_waf_nft_private_nets "$extra_cidr")"
    mgmt_block="    ip saddr { ${nets} } tcp dport { ${port_list} } accept"
  fi

  local edge_block=""
  if [[ "$edge" == "1" ]]; then
    edge_block="    tcp dport { 80, 443 } accept"
  fi

  mkdir -p "$(dirname "$EASY_WAF_NFT_RULES")"
  cat >"$EASY_WAF_NFT_RULES" <<EOF
#!/usr/sbin/nft -f
# Managed by Easy Home WAF — prefer GUI/API; manual edits may be overwritten.

table inet easy_waf {
  chain input {
    type filter hook input priority filter; policy drop;
    ct state established,related accept
    iifname "lo" accept
    tcp dport 22 accept
${mgmt_block:+
$mgmt_block}
${edge_block:+
$edge_block}
    icmp type echo-request limit rate 5/second accept
    icmpv6 type { echo-request, nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept
  }
}
EOF
  chmod 0644 "$EASY_WAF_NFT_RULES"
}

# Keep the management ports closed to everything but the configured networks,
# whatever the managed ruleset says. The API can replace that ruleset, so the
# restriction lives in a root-owned file it cannot write: a drop in any base
# chain is final, and easy-waf-hostd reloads this file after every ruleset it
# loads. Addresses are matched by source, not iifname "lo": a netdev rule could
# redirect outside traffic onto lo. mgmt_lan=0 means the operator runs the
# firewall, so nothing is imposed.
easy_waf_nft_write_guard() {
  local mgmt_lan="${1:-1}"
  local mgmt_ports="${2:-8000 8443}"
  local extra_cidr="${3:-}"

  if [[ "$mgmt_lan" != "1" ]]; then
    rm -f "$EASY_WAF_NFT_GUARD"
    return 0
  fi
  local port_list="" p
  for p in $mgmt_ports; do
    [[ -n "$port_list" ]] && port_list+=", "
    port_list+="$p"
  done
  mkdir -p "$(dirname "$EASY_WAF_NFT_GUARD")"
  cat >"$EASY_WAF_NFT_GUARD" <<EOF
#!/usr/sbin/nft -f
# Managed by the Easy Home WAF installer. Root-only by design: see docs/SECURITY.md.
# Replaced atomically, so whatever a ruleset did to this table does not survive.
table inet easy_waf_guard
delete table inet easy_waf_guard

table inet easy_waf_guard {
  chain input {
    type filter hook input priority filter - 10; policy accept;
    ip saddr { $(easy_waf_nft_private_nets "$extra_cidr") } tcp dport { ${port_list} } accept
    ip6 saddr ::1 tcp dport { ${port_list} } accept
    tcp dport { ${port_list} } drop
  }
}
EOF
  chmod 0644 "$EASY_WAF_NFT_GUARD"
}

easy_waf_nft_ensure_main_conf() {
  if [[ ! -f "$EASY_WAF_NFT_CONF" ]]; then
    cat >"$EASY_WAF_NFT_CONF" <<EOF
#!/usr/sbin/nft -f
flush ruleset
include "/etc/nftables/easy-waf.nft"
EOF
  fi
  if ! grep -qF 'include "/etc/nftables/easy-waf.nft"' "$EASY_WAF_NFT_CONF" 2>/dev/null; then
    printf '\ninclude "/etc/nftables/easy-waf.nft"\n' >>"$EASY_WAF_NFT_CONF"
  fi
  # A wildcard, so a boot does not fail when the guard is absent (mgmt_lan=0).
  if ! grep -qF 'include "/etc/nftables/easy-waf-guard*.nft"' "$EASY_WAF_NFT_CONF" 2>/dev/null; then
    printf 'include "/etc/nftables/easy-waf-guard*.nft"\n' >>"$EASY_WAF_NFT_CONF"
  fi
}

easy_waf_nft_apply() {
  command -v nft &>/dev/null || {
    echo "[easy-waf] nft: binary not found" >&2
    return 1
  }
  if ! nft -c -f "$EASY_WAF_NFT_RULES" 2>/dev/null; then
    echo "[easy-waf] nft: config check failed for $EASY_WAF_NFT_RULES" >&2
    return 1
  fi
  nft -f "$EASY_WAF_NFT_RULES"
  if [[ -f "$EASY_WAF_NFT_GUARD" ]]; then
    nft -f "$EASY_WAF_NFT_GUARD"
  else
    nft delete table inet easy_waf_guard 2>/dev/null || true
  fi
  echo "[easy-waf] nftables: applied $EASY_WAF_NFT_RULES"
}

# Install ruleset + enable nftables.service (idempotent).
easy_waf_nft_configure_appliance() {
  local mgmt_lan="${1:-1}"
  local mgmt_ports="${2:-8000 8443}"
  local edge="${3:-1}"
  local extra_cidr="${4:-}"

  easy_waf_nft_write_ruleset "$mgmt_lan" "$mgmt_ports" "$edge" "$extra_cidr"
  easy_waf_nft_write_guard "$mgmt_lan" "$mgmt_ports" "$extra_cidr"
  easy_waf_nft_ensure_main_conf
  easy_waf_nft_apply || return 1

  if command -v systemctl &>/dev/null; then
    systemctl enable nftables 2>/dev/null || true
    systemctl restart nftables 2>/dev/null || systemctl start nftables 2>/dev/null || true
  fi
  # Ubuntu may ship ufw — disable to avoid fighting our ruleset.
  if systemctl is-enabled ufw &>/dev/null 2>&1; then
    systemctl disable --now ufw 2>/dev/null || true
    echo "[easy-waf] disabled ufw (host firewall is nftables/easy-waf)"
  fi
}
