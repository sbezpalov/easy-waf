#!/usr/bin/env bash
# Installs the candidate edge in a disposable Ubuntu CI container.
set -euo pipefail
# shellcheck source=/dev/null
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 26.04 ]]
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl gnupg
fingerprint=3D653970FBAB0A890E4E4E9A0F14D8B0CF4EFE96
key=$(mktemp)
trap 'rm -f "$key"' EXIT
curl -fsSL --retry 3 "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$fingerprint" -o "$key"
actual=$(gpg --batch --show-keys --with-colons "$key" | awk -F: '$1=="pub"{primary=1;next} primary && $1=="fpr"{print $10;primary=0}')
[[ $actual == "$fingerprint" ]]
install -m 0644 "$key" /etc/apt/keyrings/haproxy-34.asc
cat >/etc/apt/sources.list.d/haproxy-34.sources <<'EOF'
Types: deb
URIs: https://ppa.launchpadcontent.net/vbernat/haproxy-3.4/ubuntu
Suites: resolute
Components: main
Signed-By: /etc/apt/keyrings/haproxy-34.asc
EOF
cat >/etc/apt/preferences.d/haproxy-34 <<'EOF'
Package: haproxy
Pin: release o=LP-PPA-vbernat-haproxy-3.4
Pin-Priority: 990

Package: *
Pin: release o=LP-PPA-vbernat-haproxy-3.4
Pin-Priority: -1
EOF
apt-get update -qq
apt-get install -y --no-install-recommends 'haproxy=3.4.*'
haproxy -v
