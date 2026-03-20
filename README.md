# Uxarion

<p align="center">
  <img src="https://github.com/rachidlaad/uxarion-security/blob/main/.github/uxarion-splash.png" alt="Uxarion splash" width="80%" />
</p>

<p align="center"><strong>Uxarion</strong> is an open-source terminal security assessment agent for local, operator-driven testing.</p>
<p align="center"><code>npm install -g uxarion</code><br />or <code>curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-security/main/install.sh | sh</code></p>

## What Uxarion is

Uxarion keeps the interactive Codex-style terminal loop, but focuses it on web and application security work:

- inspect targets and keep context across turns
- use a local model backend with your own API key
- run security workflows from the terminal
- capture evidence, findings, and reports
- integrate with tools such as ZAP

Uxarion is local-first. You bring the target scope, tooling, and API key; Uxarion helps you drive the workflow from one terminal UI.

## Project home

- Source, releases, issues, and discussions: [github.com/rachidlaad/uxarion-security](https://github.com/rachidlaad/uxarion-security)
- Canonical install command: `npm install -g uxarion`
- Direct GitHub install: `curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-security/main/install.sh | sh`

GitHub is the canonical public home for Uxarion today. The public website and docs site can be layered on top later without changing the install or update path.

## Quickstart

### Install

```bash
npm install -g uxarion
```

or

```bash
curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-security/main/install.sh | sh
```

### Launch

```bash
uxarion
```

### Add your API key

Run `uxarion`, then use `/apikey` inside the terminal UI to save a key for future runs. You can also export `OPENAI_API_KEY` if you prefer environment-based setup.

## Updates

Uxarion checks [GitHub Releases](https://github.com/rachidlaad/uxarion-security/releases) on startup. The version check comes from the `uxarion-security` repo, and the command shown in the UI depends on how Uxarion was installed:

- npm installs are prompted with `npm install -g uxarion@latest`
- bun installs are prompted with `bun install -g uxarion@latest`
- source checkout installs can keep using `uxarion update`

## Documentation

- [Install and build guide](./docs/install.md)
- [Contribution guide](./CONTRIBUTING.md)
- [Security policy](./SECURITY.md)
- [License](./LICENSE)
- [Open source fund](./docs/open-source-fund.md)

## License

Uxarion is licensed under the [Apache-2.0 License](./LICENSE).
