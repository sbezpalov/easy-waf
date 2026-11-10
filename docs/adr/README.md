# Architecture Decision Records

Decisions that are expensive to reverse, with the reasoning that produced them.
A record is written when a choice constrains later work — not for every change.

Format: context (what forced a decision), the options actually considered, the
decision, and the consequences including the ones we accepted reluctantly.
Records are immutable once accepted: a later decision supersedes an earlier one
rather than editing it, so the history of *why* stays readable.

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-packaging-and-installer.md) | Packaging: how Easy Home WAF gets onto an appliance | accepted |
| [0002](0002-mcp-server.md) | An MCP server for management and diagnostic verbs | proposed |
| [0003](0003-docker-edge-only.md) | A Docker image that is only the edge | proposed |
| [0004](0004-panel-totp.md) | A second factor for the management panel | proposed |
| [0005](0005-forward-auth.md) | Forward authentication in front of a published application | proposed |
| [0006](0006-coraza-crs.md) | What kind of WAF this project is | proposed |

Earlier architectural context that predates this directory:

- [ARCHITECTURE.md](../ARCHITECTURE.md) — components, data flow, config lifecycle
- [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) — requirements, acceptance criteria and where each is implemented
