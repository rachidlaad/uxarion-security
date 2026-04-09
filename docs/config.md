# Configuration

Uxarion reads configuration from `~/.uxarion/config.toml`.

## Connecting to MCP servers

Uxarion can connect to MCP servers configured in `~/.uxarion/config.toml`.

## Model providers

Uxarion defaults to an API-backed provider. Users can switch future sessions to `ollama` or `lmstudio` from inside the terminal UI with `/provider`.

The equivalent config keys are:

- `model_provider`
- `oss_provider`

If you change providers from the UI, Uxarion saves the new default and applies it on the next session start.

Default local provider endpoints:

- `ollama`: `http://localhost:11434/v1`
- `lmstudio`: `http://localhost:1234/v1`

Typical local-provider flow:

1. Start Ollama or LM Studio
2. Launch `uxarion`
3. Run `/provider ollama` or `/provider lmstudio`
4. Restart Uxarion
5. Run `/provider status` to verify the active backend

## ZAP integration

Uxarion stores ZAP settings under `[security.zap]`.

Example:

```toml
[security.zap]
enabled = true
base_url = "http://127.0.0.1:8080"
api_key = ""
```

Resolution order:

1. `UXARION_ZAP_BASE_URL` / `UXARION_ZAP_API_KEY`
2. `~/.uxarion/config.toml`
3. built-in default `http://127.0.0.1:8080`

Typical ZAP flow:

1. Start ZAP with the API enabled
2. Launch `uxarion`
3. Save the correct ZAP API address with `/zap url http://host:port`
4. If your ZAP API key is required, save it with `/zap key <value>`
5. Run `/zap status`
6. Restart Uxarion before running new ZAP-backed scans

Common addresses:

- Same Linux or macOS machine: `http://127.0.0.1:8080`
- Windows ZAP with Ubuntu/WSL Uxarion: use the Windows host IP instead of `127.0.0.1`, for example `http://172.17.160.1:8080`

If ZAP has `Disable the API key` enabled, you do not need to set `api_key` in Uxarion.

## Anonymous Uxarion telemetry

Uxarion can optionally send anonymous product-usage events to a team-controlled HTTPS endpoint.

The config lives under `[uxarion_telemetry]`.

Example:

```toml
[uxarion_telemetry]
enabled = true
endpoint = "https://<project-ref>.supabase.co/functions/v1/telemetry-events"
```

Current event types:

- `app_opened`
- `session_started`
- `report_generated`

Current metadata includes only product-level fields such as:

- app version
- OS and architecture
- install channel
- provider id and kind
- active profile
- whether security mode was active

Uxarion telemetry does not need ChatGPT auth, but it still respects the global analytics opt-out.
If `[analytics].enabled = false`, Uxarion telemetry is disabled even when `[uxarion_telemetry].enabled = true`.

## Apps (Connectors)

Use `$` in the composer to insert a connector; the popover lists accessible
apps. The `/apps` command lists available and installed apps. Connected apps appear first
and are labeled as connected; others are marked as can be installed.

## Notify

Uxarion can run a notification hook when the agent finishes a turn.

When Uxarion knows which client started the turn, the legacy notify JSON payload also includes a top-level `client` field. The TUI reports `codex-tui`, and the app server reports the `clientInfo.name` value from `initialize`.

## JSON Schema

The generated JSON Schema for `config.toml` lives at `codex-rs/core/config.schema.json`.

## SQLite State DB

Uxarion stores the SQLite-backed state DB under `sqlite_home` (config key) or the
`CODEX_SQLITE_HOME` environment variable. When unset, WorkspaceWrite sandbox
sessions default to a temp directory; other modes default to `CODEX_HOME`.

## Notices

Uxarion stores "do not show again" flags for some UI prompts under the `[notice]` table.

## Plan mode defaults

`plan_mode_reasoning_effort` lets you set a Plan-mode-specific default reasoning
effort override. When unset, Plan mode uses the built-in Plan preset default
(currently `medium`). When explicitly set (including `none`), it overrides the
Plan preset. The string value `none` means "no reasoning" (an explicit Plan
override), not "inherit the global default". There is currently no separate
config value for "follow the global default in Plan mode".

## Realtime start instructions

`experimental_realtime_start_instructions` lets you replace the built-in
developer message Uxarion inserts when realtime becomes active. It only affects
the realtime start message in prompt history and does not change websocket
backend prompt settings or the realtime end/inactive message.

Ctrl+C/Ctrl+D quitting uses a ~1 second double-press hint (`ctrl + c again to quit`).
