# Contributing to Easy Home WAF

Thank you for looking at this. The project is small and opinionated, so this
document is mostly about what will save you a wasted evening.

**Security problems do not go here.** See [SECURITY.md](SECURITY.md) for private
reporting. Participation is covered by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## What this project is (and is not)

Easy Home WAF is an **appliance**, not a library. It targets **Ubuntu 24.04 LTS
only** and assumes it owns HAProxy, nftables and its own PostgreSQL schema on that
host. Contributions that add portability to other distributions, or that make a
component optional "just in case", will usually be declined — every supported
combination is a combination that has to keep working on a box protecting
somebody's home network.

Things that are very welcome:

- bug fixes with a test that fails before and passes after;
- security hardening, especially around `easy-waf-hostd` and generated HAProxy config;
- documentation that corrects something wrong or unclear;
- new per-application security controls that fit the existing profile model.

Worth opening an issue **before** writing code:

- new dependencies (the binary set is deliberately small);
- anything that changes the database schema;
- new privileged operations in the broker — each one widens the root attack surface
  and needs a design discussion first;
- UI features (the UI is embedded and hand-written, without a build step).

## Documentation and translations

`docs/` is written in **English**, and English is canonical: when a translation
and the English text disagree, the English one is right. Three documents also
exist in Russian — `QUICKSTART.ru.md`, `SECURITY.ru.md`, `TROUBLESHOOTING.ru.md`
— because they are the ones an operator reads while something is broken.

If you change one of those three, either update the Russian file in the same pull
request or say in the PR that it now lags. A translation that quietly drifts is
worse than none, particularly in `SECURITY.ru.md`, where the difference between
"is rejected" and "is currently not checked" is the whole point of the sentence.
Each translated file carries the version it was translated from in its header
line; bump it when you refresh the text.

Translations of the other documents are welcome, but each one is a maintenance
commitment — open an issue first.

## Development setup

You need Go (version in [`go.mod`](go.mod)), `make`, and a PostgreSQL for anything
touching the store.

```bash
git clone https://github.com/sbezpalov/easy-waf.git
cd easy-waf
docker compose up -d          # dev PostgreSQL only
export DATABASE_URL='postgres://easywaf:easywaf@127.0.0.1:5432/easywaf?sslmode=disable'
make build
./dist/easy-waf-api -state-dir ./data -listen-http 127.0.0.1:8000 -listen-https 127.0.0.1:8443
```

Print the one-time enrollment secret to log in — there is no default password:

```bash
./dist/easy-waf-admin print-enrollment
```

**Linux only.** Development on Windows works through WSL or Git Bash, but shell
scripts must keep **LF** endings (`.gitattributes` enforces `scripts/**/*.sh text eol=lf`;
bash on Linux fails on CRLF with `$'\r': command not found`). Never commit `.exe`
or `.dll` artifacts — `scripts/check-linux-artifacts.sh` fails the build if you do.

## Before you open a pull request

Run what CI runs:

```bash
make ci     # go vet + golangci-lint + go test ./... + make verify
```

CI additionally runs, and you should too if you touch the relevant area:

```bash
go test -race ./...                                    # concurrency
go test ./internal/haproxy/... -tags=integration \
  -run TestGoldenConfigsPassHaproxyCheck               # needs haproxy in PATH
```

`golangci-lint` is pinned (see `GOLANGCI_LINT_VER` in the [Makefile](Makefile));
please use that version, since newer ones surface different findings and turn the
pipeline red for reasons unrelated to your change.

If you changed HAProxy rendering, regenerate the golden fixtures and **read the
diff** — it is the review's main evidence that the change does what you meant:

```bash
make golden-update
git diff internal/haproxy/testdata/golden
```

For a change that only a real appliance can prove (migrations, systemd units,
reload behaviour), say so in the PR and, if you can, run
`sudo bash scripts/smoke-appliance.sh` on a test VM and paste the summary.

## Code expectations

- **Comments explain why, not what.** The codebase deliberately records the reason
  a check exists — what attack it stops, what broke without it. Keep that up; a
  comment restating the code will be asked to go.
- **Fail closed.** When a check cannot be performed (a file unreadable, an account
  unresolvable), refuse rather than continue. There are several places where the
  opposite was a bug.
- **Validate on the privileged side.** A check in the API is advisory: the broker
  re-validates everything it is given, because the threat model includes a
  compromised API.
- Errors get context (`fmt.Errorf("...: %w", err)`); no silent `_ =` on anything
  whose failure changes behaviour.
- Shell scripts: `set -euo pipefail`, shellcheck-clean, no secrets in `argv`
  (command lines are world-readable — use `curl --config -` or a file).

## Commit messages and pull requests

Conventional-commit prefixes are used (`feat:`, `fix:`, `docs:`, `refactor:`,
`chore:`, with an optional scope like `fix(security):`). The subject says what
changed; the body says **why it mattered** — for a security fix, what an attacker
could do before it.

One logical change per pull request. A refactor bundled with a behaviour change
makes review much harder, and this project reviews security-relevant code closely.

Update [`CHANGELOG.md`](CHANGELOG.md) under `## [Unreleased]` for anything a user
or operator would notice.

## Releases

Maintainers only: bump [`VERSION`](VERSION), close the `[Unreleased]` section as
`## [X.Y.Z] - YYYY-MM-DD`, align the version markers in `docs/`, tag `vX.Y.Z`.
Pushing the tag triggers [`release.yml`](.github/workflows/release.yml), which
builds the tarball, publishes `SHA256SUMS`, and takes the release notes from the
matching CHANGELOG section — a missing section fails the build on purpose.

## License

By contributing you agree that your work is licensed under
[Apache-2.0](LICENSE), like the rest of the project.
