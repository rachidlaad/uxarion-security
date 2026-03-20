# Contributing to Uxarion

Thanks for helping improve Uxarion.

## Before you open a pull request

- Open an issue or discussion first for large changes, new integrations, or behavior changes.
- Keep one pull request focused on one problem.
- If the change affects user-visible behavior, update the relevant docs.
- If the change affects CLI or TUI output, add or update tests and snapshots.

## Contribution rules

- Stay within the project scope: local, operator-driven security assessment workflows.
- Do not add malware, persistence, destructive payloads, credential theft, denial-of-service features, or policy-bypass features.
- Keep security tooling scoped, evidence-oriented, and operator-controlled.
- Prefer narrowly scoped, reviewable patches over broad refactors.
- Do not commit secrets, tokens, API keys, or private customer data.

## Development expectations

- Branch from `main`.
- Run formatting and the relevant tests before opening a pull request.
- Add or update tests for behavior changes.
- Update docs when config, install, update, or user-facing workflows change.

## Pull request checklist

- The change is clearly described.
- Tests cover the new or changed behavior.
- Documentation is updated where needed.
- The change does not widen unsafe behavior outside the intended security-testing scope.

## Responsible disclosure

If you found a security issue in Uxarion itself, do not open a public issue. Follow the instructions in [SECURITY.md](./SECURITY.md).

## License

By contributing to this repository, you agree that your contributions will be licensed under the Apache-2.0 license used by this project.
