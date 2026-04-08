# Handoff

This file is the fast handoff for maintainers and AI workers.

## Read this first

1. `docs/project/current-state.md`
2. `docs/project/architecture.md`
3. `docs/project/known-issues.md`
4. the relevant GitHub issue

## Current source of truth

- repo: `rachidlaad/uxarion`
- branch: `main`

Do not assume the legacy `codex-hacker` fork is current.

## Current product focus

Short-term priorities:

- make install and update flows reliable
- improve pentest workflow quality
- strengthen evidence and reporting
- keep provider and ZAP setup understandable

## Where key work usually lands

- provider behavior: `codex-rs/core` and `codex-rs/tui`
- report generation: `codex-rs/core/src/security/mod.rs`, `codex-rs/core/src/tools/handlers/security.rs`, `codex-rs/tui/src/chatwidget/reporting.rs`, bundled system skill files under `codex-rs/skills/src/assets/samples/security-reporting/`
- update prompts and checks: `codex-rs/tui/src/updates.rs`, `codex-rs/tui/src/update_action.rs`
- npm/runtime distribution: `codex-cli/bin/uxarion.js`, `codex-cli/package.json`
- public docs: `README.md`, `docs/config.md`, `docs/install.md`
- runtime artifacts: `releases/`

## Expectations for agents and maintainers

- update docs whenever config, install, update, or public workflow behavior changes
- prefer narrowly scoped changes
- do not put secrets in tracked repo files
- use the roadmap issue before starting broad work
- leave a clear release note or commit message when changing user-facing behavior

## Before opening or merging a release change

Check:

- version bump is consistent
- runtime archive exists
- npm metadata matches the runtime version
- install/update docs still point at the right repo

## Current private-context policy

Tracked repo files are for public and contributor-visible context only.

If you need local-only context for a maintainer or AI worker:

- use ignored local files such as `.codex/`
- use local env vars
- do not hide sensitive notes in tracked markdown
