# Security Policy

Thank you for helping keep Uxarion secure.

## Reporting Security Issues

If you discover a vulnerability in Uxarion itself, do not open a public issue.

Use GitHub private vulnerability reporting for this repository when available. If private reporting is not available in the UI yet, contact the maintainers privately before public disclosure.

Please include:

- affected version
- operating system and install method
- reproduction steps
- impact summary
- logs, screenshots, or proof-of-concept details when safe to share

## Scope

This policy covers vulnerabilities in:

- the Uxarion CLI and TUI
- install and update scripts
- published release artifacts
- repository-controlled integrations and default prompts

## Out of scope

The following are not treated as security vulnerabilities in Uxarion itself:

- issues in third-party services or dependencies without a Uxarion-specific exploit path
- findings against targets you are testing with Uxarion
- self-inflicted exposure from user-supplied API keys, targets, or test infrastructure

## Disclosure expectations

- Give maintainers reasonable time to investigate and ship a fix before public disclosure.
- Keep reports factual, reproducible, and scoped to Uxarion itself.
- Do not use destructive testing against infrastructure you do not own or control.
