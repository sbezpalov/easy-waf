# .ai/ — раскладка AI-инструментов

**Источник истины — [`../AGENTS.md`](../AGENTS.md)** (читается нативно Cursor,
Antigravity/Gemini и др.). Остальные файлы — тонкие редиректы/специфика.

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
