#!/usr/bin/env bash
# Print the acceptance items that this repository cannot close.
# A zero exit means the checklist was printed. It does not mean AC-03, AC-04
# or AC-05 passed, and it does not issue a Let's Encrypt certificate.
#
# See docs/ACCEPTANCE.md.

set -euo pipefail

cat <<'EOF'
Easy Home WAF — manual acceptance

This script does not talk to Let's Encrypt, your DNS provider, or your router.
Tick the items in docs/ACCEPTANCE.md on the appliance. CI already covers the
container CrowdSec test and haproxy -c on generated config; that is not a
substitute for the list below.

[ ] AC-03 HTTP-01 against the real Let's Encrypt, trusted in a browser
[ ] AC-03 DNS-01 against the real Let's Encrypt with the provider you use
[ ] AC-03 renewal replaces the certificate HAProxy serves
[ ] AC-03 a broken challenge becomes failed, shows on the dashboard, and warns in the easy-waf-acmed journal
[ ] AC-03 if notify_webhook_url is set, one POST arrives and the journal does not contain the URL
[ ] AC-04 a client outside the LAN reaches a published name (WAN forward + DNS)
[ ] AC-05 on this host, a CrowdSec decision makes HAProxy return 403, deleting it restores access, and stopping the bouncer fails open
[ ] Clean install: sudo bash scripts/install.sh && sudo bash scripts/smoke-appliance.sh
[ ] Upgrade from an appliance actually running 1.6.0: sudo bash scripts/upgrade.sh, smoke, one Apply

Management listener (not a change to perform): install.sh keeps
EASY_WAF_LISTEN_HTTPS=0.0.0.0:8443 and nftables limits that port to loopback
and RFC1918. Loopback-only is EASY_WAF_LISTEN_HTTPS=127.0.0.1:8443.
EOF
