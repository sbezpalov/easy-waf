# Release candidate acceptance record

Copy this template into a private release evidence directory for each candidate.
All rows begin **Not run**; a template, checklist output or old green CI result
is not evidence of a pass. Use **Pass / Fail / Blocked / Not run**, with actual
observations and sanitized log/artifact references. Never attach credentials,
session tokens, private PEMs, DNS environment files or full secret-bearing dumps.

- Candidate version/tag and exact commit:
- Built artifact filenames, architectures and SHA-256:
- Signature verification result and trusted workflow identity:
- Test date/time with timezone; tester:
- Isolated Ubuntu 24.04 host identifier and architecture:
- Starting installed version/checksum for upgrade; VM snapshot/backup reference:
- HAProxy/PostgreSQL/systemd versions:
- Test public names, DNS provider and external client network (no credentials):

## Repository and artifact gates

| Gate | Result | Evidence for this candidate |
|------|--------|-----------------------------|
| Required CI lint/test/verify; DB integration actually executed | Not run | |
| Required Linux race/integration and real HAProxy validation | Not run | |
| Body policy, CrowdSec and systemd/APT E2E | Not run | |
| amd64 and arm64 packages/tarballs, manifests and signatures | Not run | |
| Release tag matches VERSION; matching changelog and package metadata | Not run | |

Local equivalents can diagnose failures but must state their OS, tool versions,
skips and exact scope. An arm64 cross-build does not prove arm64 appliance boot.

## Appliance acceptance

Use [the procedure](ACCEPTANCE.md); one result applies only to the named candidate
and starting host state. Keep before/after observations where the test mutates
state. Stop on a failure and record recovery, rather than marking later rows pass.

| Criterion | Result | Required evidence |
|-----------|--------|-------------------|
| AC-01 clean installation | Not run | Actual installer output, service/readiness/smoke results on clean Ubuntu |
| Upgrade from deployed 1.6.0 | Not run | Starting API/binary/package versions and schema, install method, matching actual upgrade, target dpkg/API versions for packages, current migration set, preserved config/certs, smoke and UI Apply |
| AC-02 UI application creation and Apply | Not run | Saved app and successful request through the resulting edge |
| AC-03 public HTTP-01 | Not run | Trusted served certificate, names/fingerprint/validity matched to DB |
| AC-03 public DNS-01 | Not run | Actual configured provider; trusted served certificate matched to DB |
| AC-03 renewal and failed challenge | Not run | New served fingerprint after renewal; failure/retry/dashboard/journal and optional notification observations |
| AC-04 WAN access | Not run | External request, client IP in HAProxy and forwarded IP at backend |
| AC-05 appliance CrowdSec | Not run | Ban 403, unban success, bouncer-down fail-open and restoration |
| AC-06 Apply and rollback | Not run | Requests before/after; invalid apply leaves previous edge working |
| AC-07 UI status | Not run | Apps/certificates/blocked views agree with actual state |
| AC-08 actual reboot and late DB recovery | Not run | Different boot IDs, recovered services/readiness and published HTTPS request |
| AC-09 WebSocket | Not run | Actual upgrade and sustained bidirectional traffic through edge |
| AC-10 backup and restore | Not run | Matched archive, exact recovered state and trusted HTTPS on a copy, writer stop/start failures and retained archive usability |

## Decision

- Unresolved failures/blocked rows and owner:
- Recovery/rollback observations:
- Approver/date and exact candidate approved (leave empty until evidence exists):

Do not use a package downgrade to bypass schema-version protection. Test the
documented matched database/state restore on a copy before relying on rollback.
