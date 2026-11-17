# Acceptance still done by hand

**English** | [Русский](ACCEPTANCE.ru.md)

Repository implementation and test coverage are indexed in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). They do not establish
acceptance of a particular release candidate on an appliance. Public ACME, WAN,
host CrowdSec, clean installation, upgrade and actual reboot still need the
checks below. `scripts/acceptance-checklist.sh` prints the outstanding checks;
a successful run only means the list was printed.

Copy [the release evidence template](RELEASE_ACCEPTANCE_TEMPLATE.md) for each
candidate. Record its exact tag/version, commit and package checksum; results
from another commit or a minimal package fixture do not approve that candidate.

Do not mark these done from a container, a mock DNS server, or a staging ACME
directory.

## AC-03 — a real certificate

On an Ubuntu 24.04 appliance that is reachable on port 80 (HTTP-01) or whose
DNS provider credentials are the ones in `dns_credentials_env_file` (DNS-01):

1. Set global `acme_staging` and each test certificate's `staging` to false,
   and use an `acme_email` you can receive mail at. Either staging flag being
   true selects the staging CA, which cannot satisfy browser trust acceptance.
2. Issue one certificate with HTTP-01 and one with DNS-01 (Cloudflare, CloudNS,
   Route53, or the webhook provider you actually use).
3. Confirm the browser trusts the public name, and that `not_after` in
   `GET /api/v1/certificates` matches the certificate HAProxy is serving.
4. Request renewal with `POST /api/v1/certificates/{id}/request-issue` and `{}`
   (or wait until the worker's 30-day window). Use an operator session, the
   normal XHR header and password-confirmation step-up required for mutations.
   An empty object preserves the stored challenge mode. On HTTP 409, reload
   the row and retry. Confirm the certificate served on 443 matches the new
   PEM referenced by the database and its recorded validity after apply; a changed
   file alone is insufficient.
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

## AC-06 — rejected Apply and revision rollback

On an isolated appliance with a matched backup, record a working published HTTPS
request and a good revision. Introduce a reversible configuration dependency
failure through the normal API, such as a CrowdSec engine absent from the configured
SPOE file, and invoke Apply. Confirm actual `haproxy -c` rejection in the private
journal, unchanged live artifacts/revisions/runtime and a successful new HTTPS
request. A malformed request rejected at the API boundary does not cover this.
Restore the setting and Apply in cleanup.

Separately apply maintenance mode to an owned test application, observe 503,
roll back to its prior good revision and observe 200 with the expected response.
Revision rollback changes artifacts, not database rows: restore the original saved
application/settings and Apply after the check. Use the matched checkpoint if
exact database/state recovery is required. Record cleanup and independent checks.

## Install and upgrade

- Clean Ubuntu 24.04: `sudo bash scripts/install.sh`, then
  `sudo bash scripts/smoke-appliance.sh`.
- Smoke HTTP probes allow up to 5 seconds to connect and 30 seconds for the
  transfer. The optional MMDB upload allows 120 seconds. An incomplete
  response fails the probe even when the server has sent HTTP 200.
- Smoke checks the daily backup timer when it is enabled. The timer must be
  active with a scheduled run or a backup in progress. A disabled or masked
  timer is reported as skipped.
- Upgrade an appliance that is actually running 1.6.0. Record its API version,
  installed binary hashes and, for package installations, dpkg version before
  starting. Authenticate the candidate input and retain a matched backup.
  Use the method matching that installation:

  - Package-managed appliance: install the verified candidate DEB with APT,
    for example `sudo apt-get -o Dpkg::Options::=--force-confold install ./easy-waf_1.6.1_amd64.deb`
    for the amd64 1.6.1 candidate. Select the actual candidate version and host
    architecture. Confirm both dpkg and API report the target version.
  - Installation without a package: run
    `sudo bash scripts/upgrade.sh /path/to/verified-binaries-or.tar.gz`.
    This path replaces binaries and does not update dpkg metadata; it is not
    the package-upgrade procedure.

  Run the same smoke script and one Apply from the UI. Confirm PostgreSQL
  migrations reached the current set, configuration/certificate files were
  preserved, and HAProxy reloaded with healthy runtime stats and a working
  published service. A tarball overwrite followed by package alignment does
  not prove the package's migration path from the original 1.6.0 schema.

## AC-08 — an actual reboot

On the isolated test appliance, record the boot ID, reboot, reconnect and confirm
the boot ID changed. Run the smoke script, check readiness and request a published
HTTPS service. Confirm API, ACME and host-management services recover, including
when PostgreSQL becomes available late. Enabled unit files and restarting a
fixture service do not establish this criterion.

## AC-10 — backup, restore and recovery

On an isolated copy, take a matched archive with the installed backup command.
Record the package identity, archive checksum and confirmed writer restart.
Make a reversible change to an owned test application, restore the archive
with the packaged command and verify the original application, certificate,
edge status and trusted HTTPS response.

Exercise failure handling on the same isolated copy. A writer that cannot stop
must prevent database work and preserve an existing archive. A backup that
saves an archive but cannot resume a writer must report the path and exit
nonzero. A restore that replaces data but cannot complete Apply or a required
service start must also exit nonzero. Confirm service recovery and archive
usability after removing the test failure. For a package rollback across
schema versions, use the matching archive and an empty database. See
[Backup and restore](BACKUP_RESTORE.md).

Write the date, the host (not its secrets), and the result next to each item
before approving the candidate named in the report. A passing container or CI
run does not fill the outstanding appliance rows automatically.
