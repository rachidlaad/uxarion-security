# Architecture

## Top-level shape

Uxarion is a single-repo project with:

- product source
- public docs
- release artifacts
- npm wrapper
- native runtime packaging

The repo is the canonical home for:

- issues
- roadmap
- releases
- install/update paths

## Main components

### Rust workspace

The main product code lives in `codex-rs/`.

Important areas:

- `codex-rs/core`
  - provider configuration
  - auth storage
  - security tooling
  - ZAP integration
  - request/response behavior
- `codex-rs/tui`
  - terminal UI
  - onboarding
  - slash commands
  - update banners
  - provider and ZAP controls
- `codex-rs/utils/*`
  - shared utilities used across the workspace

### npm wrapper

The npm distribution layer lives in `codex-cli/`.

Important files:

- `codex-cli/package.json`
- `codex-cli/bin/uxarion.js`

The wrapper:

- detects the platform
- downloads the matching runtime archive if needed
- extracts it into the local runtime cache
- launches the native binary
- sets install-channel environment markers for the child process

### Release artifacts

Versioned runtime archives are committed under:

- `releases/vX.Y.Z/`

Those artifacts are used for:

- GitHub Releases assets
- the raw GitHub download path used by the npm wrapper

## Provider model

Public product behavior:

- default provider: API
- optional local providers: Ollama and LM Studio
- security profile honors the configured provider instead of forcing the local Responses-compatible backend

Important note:

- internal provider and crate plumbing still contains inherited `codex` naming
- public behavior and docs should stay Uxarion-branded

## ZAP integration model

Uxarion uses the ZAP API directly.

It does not script the desktop UI.

Current configuration paths:

- slash commands such as `/zap`, `/zap status`, `/zap url`, `/zap key`
- config file values
- env overrides:
  - `UXARION_ZAP_BASE_URL`
  - `UXARION_ZAP_API_KEY`

Default expectation:

- same-machine setups use `http://127.0.0.1:8080`
- WSL + Windows ZAP setups may need the Windows host IP instead

## Reporting model

Uxarion reporting is now a hybrid:

- persisted security session state remains the source of truth
- `/findings` stays local and deterministic
- `/report` runs as a normal model turn with the bundled `security-reporting` system skill
- the low-level `report_write` tool remains the canonical local save path for Markdown artifacts

Current intent:

- the model can inspect saved findings, evidence files, and screenshots to draft a better report
- report output is still written locally to the canonical session report path
- the user-facing report flow is no longer the old app-side deterministic `/report` action

## Update model

Current update source:

- GitHub releases from `rachidlaad/uxarion`

Channel-specific update actions:

- npm: `npm install -g uxarion@latest`
- bun: `bun install -g uxarion@latest`
- source checkout: `uxarion update`

Current caveat:

- the update banner depends on cached release metadata and may not surface same-day releases immediately

## Config and local state

Public runtime state is stored under `CODEX_HOME`, which the npm wrapper defaults to the Uxarion home directory.

Common local files include:

- auth storage
- config
- sessions
- cached update metadata

Tracked repo files must not contain secrets.

Private operator or local-agent notes should live in ignored local files such as `.codex/`.
