# Architecture Decision Records

Decisions that are expensive to reverse, with the reasoning that produced them.
A record is written when a choice constrains later work — not for every change.

Format: context (what forced a decision), the options actually considered, the
decision, and the consequences including the ones we accepted reluctantly.
Records are immutable once accepted: a later decision supersedes an earlier one
rather than editing it, so the history of *why* stays readable.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-packaging-and-installer.md) | Packaging: how Easy Home WAF gets onto an appliance | proposed |

Earlier architectural context that predates this directory:

- [ARCHITECTURE.md](../ARCHITECTURE.md) — components, data flow, config lifecycle
- [PROMPTS_ALIGNMENT.md](../PROMPTS_ALIGNMENT.md) — requirements ↔ implementation matrix
