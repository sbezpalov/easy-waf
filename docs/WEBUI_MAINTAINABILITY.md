# Web UI maintainability plan

Status: **active phased refactor**. Phase 1 added a deterministic, manifest-based
Go generator and extracted CSS tokens without changing the delivered
`dist/index.html` bytes. This document does not authorize a runtime, dependency,
CSP, API, or permission change.

## Problem

`internal/webui/dist/index.html` currently contains the markup, styles, API
client, state, renderers and interactions for every management screen. The
single file is intentionally dependency-free and easy to embed, but its size
makes otherwise local changes expensive to review and increases regression
risk. Several interaction tests also locate JavaScript regions by source
markers, so an unplanned split would make both production behavior and tests
fragile at the same time.

## Security constraints

The source layout may change only while all of these runtime properties remain
true:

- `embed.FS` contains every served UI asset; no CDN, remote script, dynamic
  import, `eval`, `new Function` or runtime package loader is introduced.
- The delivered page has exactly one plain inline `<script>` block.
- `internal/webui/csp.go` derives the exact SHA-256 allowlist from that embedded
  block. `script-src 'unsafe-inline'` and a broad `script-src 'self'` are not
  acceptable substitutes.
- `connect-src 'self'`, `form-action 'self'`, `frame-ancestors 'none'`,
  `object-src 'none'` and the existing security headers remain unchanged.
- Generated output is deterministic across Windows and macOS checkouts,
  including the browser's CRLF-to-LF script normalization used by the CSP hash.
- The change does not broaden viewer/admin capabilities or add a host-broker
  operation.

An external `app.js` is therefore not the first step. Serving it under a broad
same-origin script policy would weaken the current exact-script guarantee. A
different external-script CSP design would require a separate security review
and browser-compatibility decision.

## Proposed target

Keep `internal/webui/dist/index.html` as committed, reviewable generated output.
Introduce source-only files under `internal/webui/src/` and a small Go generator
owned by this repository. The generator concatenates stable sections into the
same delivery shape:

```text
internal/webui/src/
  shell.html
  styles/
    tokens.css
    shell.css
    components.css
    screens.css
  scripts/
    api.js
    state.js
    primitives.js
    applications.js
    protection.js
    host.js
    observe.js
  screens/
    dashboard.html
    applications.html
    ...
        |
        | deterministic Go generator
        v
internal/webui/dist/index.html
  one inline style block
  one inline script block
```

The source files are not served. File order is an explicit manifest rather than
a directory glob, and the generator rejects missing, duplicate or unexpected
sections. It performs no template evaluation of untrusted input.

### Current implementation

Phase 1 intentionally starts with only three source partials:

```text
internal/webui/src/
  document-before-tokens.html
  styles/tokens.css
  document-after-tokens.html
```

`internal/webui/generate.go` invokes the repository-owned generator with
`go generate ./internal/webui`. The manifest is explicit, source newlines are
normalized to LF, and `generator_test.go` requires the assembled bytes to equal
the committed `dist/index.html`. The large trailing partial remains temporary;
later phases split it by responsibility without changing delivery shape. Its
narrow `whitespace=-trailing-space` Git attribute preserves six pre-existing
end-of-line spaces for the byte-identical first commit; remove that exception
when the affected JavaScript regions are split and regenerated together.

## Delivery phases

### 0. Characterize the current bundle

Keep the existing cross-screen browser matrix, long-value fixtures, keyboard
report, CSP tests and full Go suite as the baseline. No source move happens in
this phase.

### 1. Add a byte-stable generator

**Implemented:** the first generated output is byte-identical to the preceding
committed page, and CSS tokens are the first independently owned source region.

Move one inert region at a time into `src/`, starting with CSS tokens. Generate
`dist/index.html` and require:

```text
go generate ./internal/webui/...
git diff --exit-code -- internal/webui/dist/index.html
```

The first generator commit must produce a page that is byte-identical to its
parent. This makes rollback a source-layout revert rather than a behavior
change.

### 2. Split markup by screen

Extract static screen sections without changing IDs, hash routes, order,
labels, classes or visible text. Run the 12-screen route/reflow/AX matrix after
each small group. Do not combine this phase with navigation redesign.

### 3. Split JavaScript by responsibility

Concatenate source modules into the existing single script in a fixed order.
First isolate leaf renderers, then screen loaders, then shared state/API code.
Global names and initialization order remain explicit until a separately
reviewed module design exists. Replace source-range tests with behavior tests as
each region moves; do not delete coverage merely because markers change.

### 4. Reduce inline styles

Move repeated presentation into generated CSS classes. Only after inline style
usage reaches zero may a separate CSP change propose removing
`style-src 'unsafe-inline'`. That hardening is desirable but is not coupled to
the source split.

### 5. Consider external assets separately

External CSS can be evaluated after the generated-source workflow is stable.
External JavaScript remains a separate security decision with CSP/SRI and
browser-support analysis; it is not required for maintainability.

## Required gates per phase

- Generator unit tests: deterministic output, manifest ordering, duplicate and
  missing section rejection, CRLF/LF equivalence where applicable.
- `TestInlineScriptHash`, `TestPageHasNoInlineEventHandlers`, security-header
  tests and an assertion that the built page still has exactly one script.
- Full Go test, vet, lint, Linux build and repository policy checks.
- Synthetic browser matrix at 390/768/1440 pixels plus 200% reflow equivalent;
  zero critical console/network failures and no page-level overflow.
- Keyboard focus, dialogs, viewer write gate, session expiry, publication,
  rollback and long-running package-operation tests.
- Generated `dist/index.html` is committed so release builds do not depend on a
  generator being installed at package-build time.

## Rollback

Each phase is a separate commit. Revert the current phase and regenerate the
previous committed `dist/index.html`; no database, API or appliance state
rollback is involved. If CSP output, generated bytes or browser behavior differ
unexpectedly, stop the split and keep the last committed monolith.

## Exit criteria

- A screen change normally touches one screen source file plus focused tests.
- Shared primitives have one implementation and behavior-level coverage.
- Generated output and CSP are reproducible on Windows and macOS.
- No runtime dependency, remote asset, permission expansion or security-policy
  weakening was introduced to obtain the source split.
