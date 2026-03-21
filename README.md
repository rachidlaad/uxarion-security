# Uxarion

<p align="center"><strong>Uxarion</strong> is an open-source terminal security assessment agent for local, operator-driven testing.</p>
<p align="center"><code>npm install -g uxarion</code><br />or <code>curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-security/main/install.sh | sh</code></p>

## What Uxarion is

Uxarion keeps an interactive terminal agent loop, but focuses it on web and application security work:

- inspect targets and keep context across turns
- use either your own API key or a local model backend
- run security workflows from the terminal
- capture evidence, findings, and reports
- integrate with tools such as ZAP

Uxarion is local-first. You bring the target scope, tooling, and API key; Uxarion helps you drive the workflow from one terminal UI.

## Project home

- Source, releases, issues, and discussions: [github.com/rachidlaad/uxarion-security](https://github.com/rachidlaad/uxarion-security)
- Canonical install command: `npm install -g uxarion`
- Direct GitHub install: `curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion-security/main/install.sh | sh`

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

### Optional: switch to a local model

Uxarion keeps the API-backed provider as the default. To use a local provider instead:

1. Start your local model server.
   - Ollama should expose an OpenAI-compatible endpoint on `http://localhost:11434/v1`
   - LM Studio should expose an OpenAI-compatible endpoint on `http://localhost:1234/v1`
2. Launch `uxarion`
3. Run `/provider ollama` or `/provider lmstudio`
4. Restart Uxarion
5. Run `/provider status` in the new session to confirm the active backend

Provider changes are saved for future sessions. Uxarion does not start Ollama or LM Studio for you, and local providers do not use your `OPENAI_API_KEY`.

## Updates

Uxarion checks [GitHub Releases](https://github.com/rachidlaad/uxarion-security/releases) on startup. The version check comes from the `uxarion-security` repo, and the command shown in the UI depends on how Uxarion was installed:

- npm installs are prompted with `npm install -g uxarion@latest`
- bun installs are prompted with `bun install -g uxarion@latest`
- source checkout installs can keep using `uxarion update`

## Documentation

- [Install and build guide](./docs/install.md)
- [Configuration guide](./docs/config.md)
- [Contribution guide](./CONTRIBUTING.md)
- [Security policy](./SECURITY.md)
- [License](./LICENSE)

## License

Uxarion is licensed under the [Apache-2.0 License](./LICENSE).
