# .ai/ — раскладка AI-инструментов

**Source of truth — [`../AGENTS.md`](../AGENTS.md).** The other files are the
entry points each tool looks up by name (`CLAUDE.md`, `GEMINI.md`,
`PERPLEXITY.md`, `.cursor/rules`). They are not a second copy of the project,
and removing them would make that tool stop reading the repository. Tool
specifics stay in the tool file. Project rules change in `AGENTS.md`.

| Инструмент | Файл | Артефакты |
|---|---|---|
| Все агенты | `AGENTS.md` | `.ai/artifacts/` |
| Cursor | `.cursorrules` → AGENTS.md; `.cursor/rules/*.mdc`; `.cursorignore` | `.cursor/artifacts/` |
| Claude (Code / Cowork) | `CLAUDE.md` → AGENTS.md; `.claude/` | `.claude/artifacts/` |
| Antigravity / Gemini | `GEMINI.md` (+ AGENTS.md) | `.antigravity/artifacts/` |
| Perplexity | `PERPLEXITY.md` (вставляемый бриф) | `.perplexity/artifacts/` |

## Правило
Меняется проект → правь **`AGENTS.md`**. Инструмент-специфика — в файле инструмента.
Артефакт — сохраняемый результат, переживающий сессию (план, ресёрч, diff, task-list).

<!-- Инициализировано init-ai-tooling.sh v2 (2026-07-05). -->
