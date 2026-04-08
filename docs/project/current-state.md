# Current State

## Product position

Uxarion is an open-source terminal security assessment agent for local, operator-driven testing.

It currently focuses on:

- scoped web and application security workflows
- exact URL/host/port/path binding when the user scopes a turn to a concrete URL
- API-backed sessions by default
- optional local-model sessions through Ollama or LM Studio
- ZAP-backed scanning through the ZAP API
- local-first evidence capture with `/findings`
- skill-backed `/report` generation that reads saved session artifacts and writes canonical Markdown reports locally

## Canonical repo and release home

- Canonical source repo: `rachidlaad/uxarion`
- Canonical public branch: `main`
- Canonical release source: GitHub Releases in the same repo
- Canonical npm package: `uxarion`

The legacy `codex-hacker` fork is no longer the source of truth.

## Current install channels

- npm: `npm install -g uxarion`
- direct install: `curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion/main/install.sh | sh`

## Current shipped version

- Latest shipped version at the time of this document: `0.1.9`

## Effective platform support

Current public runtime support is effectively:

- Linux `x86_64`

Other platforms may exist in source or packaging scaffolding, but the reliable public runtime path is Linux `x86_64` first.

## Important current behaviors

- API provider is the default provider.
- Security mode binds exact scoped URLs to the provided host, port, and path instead of inferring alternate routes.
- `/provider` supports API, Ollama, and LM Studio.
- ZAP is configurable through `/zap`.
- npm installs download the native runtime from the `uxarion` repo release path.
- Update checks read from the `uxarion` GitHub releases feed.

## Important current limits

- The updater currently relies on a cached `version.json` and can miss same-day releases until the cache is refreshed.
- Full `codex-tui` test and clippy runs are still expensive on mounted Windows workspaces.
- Internal crate and folder names still use `codex-*`; public branding is Uxarion.

## Maintainer rule of thumb

Optimize public product surfaces first:

- README
- install/update flow
- TUI text and prompts
- provider and ZAP setup
- release reliability

Do not prioritize large internal renames unless they clearly improve product behavior or contributor velocity.
