# Code of Conduct

This is a small project maintained by one person. The rules are short because
they only need to cover what actually goes wrong in a repository like this one.

## What is expected

- **Be direct about the code and considerate about the person.** "This validation
  runs on the wrong side of the privilege boundary" is a good review comment.
  "Did you even think about this?" is not, and it carries no extra information.
- **Assume the other side has a reason.** Homelab setups differ wildly. A report
  that looks absurd usually means someone's environment is not yours.
- **Respect the answer "no".** Not every feature belongs in an appliance whose
  main value is a small, auditable attack surface. Scope decisions are explained
  in [CONTRIBUTING.md](CONTRIBUTING.md); disagreeing with one is fine, relitigating
  it in every thread is not.
- **Keep other people's networks out of it.** Do not post someone's public IP,
  hostname or certificate details, even to make a point about a bug. When
  attaching logs or configuration, redact first.

## What is not acceptable

Harassment, personal attacks, discrimination, sexualised content, sustained
disruption of discussions, and publishing anyone's private information.

Two things specific to a security project:

- Publicly dropping an unfixed vulnerability instead of using
  [private reporting](SECURITY.md), when a coordinated path is available and the
  maintainer is responding.
- Pressuring anyone into running untrusted code or disabling protections on an
  appliance that faces the internet.

## Scope

Applies to issues, pull requests, discussions and any other project space, and to
public behaviour that represents the project.

## Enforcement

Report privately to the maintainer through the contact links on the repository
owner's GitHub profile ([@sbezpalov](https://github.com/sbezpalov)), with
`easy-waf conduct` in the subject. Reports stay private; nothing sent to the
maintainer will be republished.

The maintainer may edit or delete comments, close threads, or block accounts,
proportionate to what happened. Deliberate harassment gets a block on the first
occurrence — there is no warning quota to exhaust.

Decisions are made by one person, which is honest about its limits: there is no
appeal body here. If that is not enough for your situation, the project's license
lets you fork it.

## Attribution

Informed by the [Contributor Covenant](https://www.contributor-covenant.org/),
rewritten for a single-maintainer security appliance rather than adopted verbatim.
