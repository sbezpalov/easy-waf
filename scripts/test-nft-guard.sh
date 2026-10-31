#!/usr/bin/env bash
# Proves with real traffic that the firewall guard keeps the management ports
# closed against a ruleset the API chose: real nft in a container with a public
# and a LAN network. What easy-waf-hostd does after a load is `nft -f <guard>`.
# Needs Docker with NET_ADMIN; not part of CI.
#
#   bash scripts/test-nft-guard.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUB=easywaf-nft-pub
LAN=easywaf-nft-lan
SRV=nft-guard-host
remove_stack() {
  docker rm -f "$SRV" >/dev/null 2>&1 || true
  docker network rm "$PUB" "$LAN" >/dev/null 2>&1 || true
}
trap remove_stack EXIT
remove_stack

docker network create --subnet 203.0.113.0/24 "$PUB" >/dev/null
docker network create --subnet 10.78.0.0/24 "$LAN" >/dev/null
docker run -d --name "$SRV" --network "$PUB" --ip 203.0.113.10 --cap-add NET_ADMIN \
  -v "$ROOT/scripts/lib:/lib-ew:ro" ubuntu:24.04 sleep 600 >/dev/null
docker network connect --ip 10.78.0.10 "$LAN" "$SRV"
docker exec "$SRV" bash -c '
  apt-get update -qq >/dev/null; apt-get install -y -qq nftables python3 >/dev/null 2>&1
  cd /tmp; (python3 -m http.server 8443 >/dev/null 2>&1 &) ; (python3 -m http.server 9999 >/dev/null 2>&1 &)
  source /lib-ew/nftables-easy-waf.sh
  easy_waf_nft_write_ruleset 1 "8000 8443" 1 ""
  easy_waf_nft_write_guard 1 "8000 8443" ""
  easy_waf_nft_ensure_main_conf
  nft -f /etc/nftables.conf'
sleep 1

failures=0
check() { # description want got
  if [[ "$2" == "$3" ]]; then
    echo "PASS: $1 ($3)"
  else
    echo "FAIL: $1: want $2, got $3"
    failures=$((failures + 1))
  fi
}
reach() { # network client-ip target-ip port -> open|closed
  if docker run --rm --network "$1" --ip "$2" curlimages/curl:8.10.1 -s -o /dev/null -m 3 "http://$3:$4/"; then
    echo open
  else
    echo closed
  fi
}
hostile() { docker exec -i "$SRV" nft -f - ; }
guard() { docker exec "$SRV" nft -f /etc/nftables/easy-waf-guard.nft; }

check "boot config: public client on management port" closed "$(reach "$PUB" 203.0.113.50 203.0.113.10 8443)"
check "boot config: LAN client on management port" open "$(reach "$LAN" 10.78.0.50 10.78.0.10 8443)"

hostile <<'NFT'
flush ruleset
table inet evil {
  chain input {
    type filter hook input priority -300; policy accept;
    tcp dport 8443 accept
  }
}
NFT
check "without the guard reload a hostile ruleset exposes the port" open "$(reach "$PUB" 203.0.113.50 203.0.113.10 8443)"
guard
check "guard reloaded: public client refused" closed "$(reach "$PUB" 203.0.113.50 203.0.113.10 8443)"
check "guard reloaded: LAN client still allowed" open "$(reach "$LAN" 10.78.0.50 10.78.0.10 8443)"
check "guard reloaded: other ports stay the ruleset's business" open "$(reach "$PUB" 203.0.113.50 203.0.113.10 9999)"

hostile <<'NFT'
table inet easy_waf_guard { flags dormant; }
NFT
check "dormant guard is a real bypass until reloaded" open "$(reach "$PUB" 203.0.113.50 203.0.113.10 8443)"
guard
check "reload undoes a dormant guard" closed "$(reach "$PUB" 203.0.113.50 203.0.113.10 8443)"

if ((failures)); then
  exit 1
fi
echo "OK: the guard holds"
