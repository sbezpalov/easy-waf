# What and why

<!-- What changed, and what problem it solves. For a security fix: what an
     attacker could do before this change. -->

Closes #

## Verification

<!-- Tick what you actually ran, and paste anything surprising. -->

- [ ] `make ci` (vet + pinned golangci-lint + tests + verify)
- [ ] `go test -race ./...`
- [ ] `go test ./internal/haproxy/... -tags=integration -run TestGoldenConfigsPassHaproxyCheck` (needs `haproxy`)
- [ ] Golden fixtures regenerated (`make golden-update`) and the diff reviewed
- [ ] Checked on a live appliance (`sudo bash scripts/smoke-appliance.sh`)
- [ ] Not applicable — documentation only

## Impact on an existing appliance

<!-- Delete what does not apply. This section is what an operator reads before
     upgrading. -->

- Database migration: no / yes (which one)
- Generated HAProxy configuration changes: no / yes (how)
- systemd units changed (needs `daemon-reload`): no / yes
- New or changed environment variables / settings: no / yes
- Behaviour that could break existing automation: no / yes

## Notes for the reviewer

<!-- Trade-offs you weighed, alternatives you rejected, anything you are unsure
     about. Saying "I am not sure this is the right layer" is useful, not weak. -->

- [ ] `CHANGELOG.md` updated under `## [Unreleased]` (or: not user-visible)
