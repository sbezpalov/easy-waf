# Acceptance still done by hand

**English** | [Русский](ACCEPTANCE.ru.md)

AC-01, AC-02 and AC-06 … AC-10 are covered by the repository (see
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)). The three below are not,
and neither is a clean install or an upgrade on hardware this repository can
reach. `scripts/acceptance-checklist.sh` prints the same list. A successful run
of that script is not a pass.

Do not mark these done from a container, a mock DNS server, or a staging ACME
directory.

## AC-03 — a real certificate

On an Ubuntu 24.04 appliance that is reachable on port 80 (HTTP-01) or whose
DNS provider credentials are the ones in `dns_credentials_env_file` (DNS-01):

1. Set `acme_staging` to false and an `acme_email` you can receive mail at.
2. Issue one certificate with HTTP-01 and one with DNS-01 (Cloudflare, CloudNS,
   Route53, or the webhook provider you actually use).
3. Confirm the browser trusts the public name, and that `not_after` in
   `GET /api/v1/certificates` matches the certificate HAProxy is serving.
4. Force a renewal (`POST /api/v1/certificates/{id}/renew` or wait until the
   worker's 30-day window) and confirm the new certificate is the one in
   `crt-list` after apply.
5. Break the challenge once (close port 80, or revoke the DNS token) and
   confirm the row becomes `failed`, the dashboard shows attention, the
   `easy-waf-acmed` journal warns within a day, and — if `notify_webhook_url`
   is set — one POST arrives and does not include the webhook URL in the journal.

## AC-04 — a client outside the LAN

From a network that is not the appliance LAN, open a published name. That
requires the WAN forward of 443 (and 80 for HTTP-01) to this host, DNS pointing
at it, and a certificate from AC-03. Record the client IP HAProxy logs and the
IP the backend sees (`X-Forwarded-For`).

## AC-05 — CrowdSec on the appliance

The nightly container test
(`scripts/test-crowdsec-e2e.sh`, `.github/workflows/e2e.yml`) already proves the
generated config returns 403 when a real bouncer says so, and fails open when
the bouncer is down. On the appliance itself:

1. `systemctl is-active crowdsec crowdsec-firewall-bouncer` is not required;
   the path under test is the HAProxy SPOE bouncer.
2. Add a decision for your test client (`cscli decisions add`).
3. Request the published name from that client and record the 403.
4. Delete the decision and record that the next request succeeds.
5. Stop the bouncer, record that traffic still passes, then start it again.

## Install and upgrade

- Clean Ubuntu 24.04: `sudo bash scripts/install.sh`, then
  `sudo bash scripts/smoke-appliance.sh`.
- Upgrade an appliance that is actually running 1.6.0:
  `sudo bash scripts/upgrade.sh`, then the same smoke script, then one Apply
  from the UI. Confirm PostgreSQL migrations reached the current set and
  HAProxy reloaded.

Write the date, the host (not its secrets), and the result next to each item
before calling 1.7.0 stable.
