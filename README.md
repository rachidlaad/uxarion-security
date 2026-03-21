# Uxarion

<p align="center"><strong>Uxarion</strong> is an open-source terminal security assessment agent for local, operator-driven testing.</p>
<p align="center"><code>npm install -g uxarion</code><br />or <code>curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion/main/install.sh | sh</code></p>

## What Uxarion is

Uxarion keeps an interactive terminal agent loop, but focuses it on web and application security work:

- inspect targets and keep context across turns
- use either your own API key or a local model backend
- run security workflows from the terminal
- capture evidence, findings, and reports
- integrate with tools such as ZAP

Uxarion is local-first. You bring the target scope, tooling, and API key; Uxarion helps you drive the workflow from one terminal UI.

## ZAP setup

Uxarion talks to ZAP through the API, not by scripting the desktop UI.

Simple setup:

1. Open ZAP and go to `Options > API`.
2. Make sure `Enabled` is checked.
3. Choose the address Uxarion should use:
   - If Uxarion and ZAP run on the same Linux or macOS machine, use `http://127.0.0.1:8080`
   - If ZAP runs on Windows and Uxarion runs inside Ubuntu/WSL, use the Windows host IP instead, for example `http://172.17.160.1:8080`
4. Launch `uxarion`.
5. Save the ZAP URL from inside Uxarion:
   - `/zap url http://127.0.0.1:8080`
   - or `/zap url http://172.17.160.1:8080`
6. If your ZAP API key is required, save it with `/zap key <value>`.
7. Run `/zap status` to verify connectivity.
8. Restart Uxarion before relying on `zap_run` in a new session.

Notes:

- If ZAP shows `Disable the API key` enabled, Uxarion does not need `/zap key`.
- If `127.0.0.1:8080` fails but ZAP is running on Windows, switch to the Windows host IP with `/zap url http://host:port`.

Useful commands:

- `/zap` opens the ZAP setup popup
- `/zap status` checks the current saved ZAP API endpoint
- `/zap url http://127.0.0.1:8080` saves a different API base URL
- `/zap key <value>` saves a ZAP API key
- `/zap clear-key` removes the saved ZAP API key
- `/zap enable` or `/zap disable` toggles ZAP-backed tooling for future sessions

Environment overrides:

- `UXARION_ZAP_BASE_URL`
- `UXARION_ZAP_API_KEY`

## Project home

- Source, releases, issues, and discussions: [github.com/rachidlaad/uxarion](https://github.com/rachidlaad/uxarion)
- Canonical install command: `npm install -g uxarion`
- Direct GitHub install: `curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion/main/install.sh | sh`

## Quickstart

### Install

```bash
npm install -g uxarion
```

or

```bash
curl -fsSL https://raw.githubusercontent.com/rachidlaad/uxarion/main/install.sh | sh
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

Uxarion checks [GitHub Releases](https://github.com/rachidlaad/uxarion/releases) on startup. The version check comes from the `uxarion` repo, and the command shown in the UI depends on how Uxarion was installed:

- npm installs are prompted with `npm install -g uxarion@latest`
- bun installs are prompted with `bun install -g uxarion@latest`
- source checkout installs can keep using `uxarion update`

## Contributing

Open issues, discussions, and pull requests in this repo are the main collaboration path for Uxarion.
