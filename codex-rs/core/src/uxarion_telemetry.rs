use crate::config::Config;
use crate::config::types::UxarionTelemetryConfig;
use crate::default_client::build_reqwest_client;
use codex_protocol::protocol::SessionSource;
use serde::Serialize;
use serde_json::Value as JsonValue;
use serde_json::json;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;
use uuid::Uuid;

const UXARION_TELEMETRY_TIMEOUT: Duration = Duration::from_secs(2);
const UXARION_MANAGED_BY_NPM_ENV_VAR: &str = "UXARION_MANAGED_BY_NPM";
const UXARION_MANAGED_BY_BUN_ENV_VAR: &str = "UXARION_MANAGED_BY_BUN";

#[derive(Clone)]
pub struct UxarionTelemetryClient {
    runtime: Arc<UxarionTelemetryRuntime>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStartedEvent {
    pub provider_id: String,
    pub provider_name: String,
    pub session_source: SessionSource,
    pub active_profile: Option<String>,
    pub security_mode_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportGeneratedKind {
    Structured,
    AiAuthored,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportGeneratedEvent {
    pub kind: ReportGeneratedKind,
    pub finding_scoped: bool,
    pub include_evidence: Option<bool>,
}

struct UxarionTelemetryRuntime {
    config: Arc<Config>,
    settings: UxarionTelemetryConfig,
    install_id: Mutex<Option<String>>,
    client: reqwest::Client,
}

enum UxarionTelemetryJob {
    AppOpened,
    SessionStarted(SessionStartedEvent),
    ReportGenerated(ReportGeneratedEvent),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UxarionTelemetryRequest {
    events: Vec<UxarionTelemetryEvent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UxarionTelemetryEvent {
    event_name: &'static str,
    install_id: String,
    app_version: &'static str,
    os: &'static str,
    arch: &'static str,
    install_channel: &'static str,
    sent_at: i64,
    properties: JsonValue,
}

impl UxarionTelemetryClient {
    pub fn new(config: Arc<Config>) -> Self {
        let settings = config.uxarion_telemetry.clone();
        tracing::debug!(
            enabled = settings.enabled,
            has_endpoint = settings.endpoint.is_some(),
            "initialized uxarion telemetry client"
        );
        let runtime = Arc::new(UxarionTelemetryRuntime {
            config,
            settings,
            install_id: Mutex::new(None),
            client: build_reqwest_client(),
        });
        Self { runtime }
    }

    pub fn track_app_opened(&self) {
        self.try_send(UxarionTelemetryJob::AppOpened);
    }

    pub fn track_session_started(&self, event: SessionStartedEvent) {
        if matches!(
            event.session_source,
            SessionSource::SubAgent(_) | SessionSource::Unknown
        ) {
            return;
        }
        self.try_send(UxarionTelemetryJob::SessionStarted(event));
    }

    pub fn track_report_generated(&self, event: ReportGeneratedEvent) {
        self.try_send(UxarionTelemetryJob::ReportGenerated(event));
    }

    fn try_send(&self, job: UxarionTelemetryJob) {
        let event_name = job.event_name();
        if !self.runtime.settings.enabled {
            tracing::debug!(
                event_name,
                "skipping uxarion telemetry event because telemetry is disabled"
            );
            return;
        }
        tracing::debug!(
            event_name,
            has_endpoint = self.runtime.settings.endpoint.is_some(),
            "dispatching uxarion telemetry event"
        );
        let runtime = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            tracing::debug!(event_name, "starting uxarion telemetry worker thread");
            let Ok(worker_runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                tracing::warn!(event_name, "failed to build uxarion telemetry runtime");
                return;
            };
            worker_runtime.block_on(async move {
                send_uxarion_telemetry_event(&runtime, job).await;
            });
        });
    }
}

impl ReportGeneratedKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Structured => "structured",
            Self::AiAuthored => "ai_authored",
        }
    }
}

impl UxarionTelemetryJob {
    fn event_name(&self) -> &'static str {
        match self {
            Self::AppOpened => "app_opened",
            Self::SessionStarted(_) => "session_started",
            Self::ReportGenerated(_) => "report_generated",
        }
    }
}

async fn send_uxarion_telemetry_event(runtime: &UxarionTelemetryRuntime, job: UxarionTelemetryJob) {
    if !runtime.settings.enabled {
        tracing::debug!("skipping uxarion telemetry send because telemetry is disabled");
        return;
    }
    let Some(endpoint) = runtime.settings.endpoint.as_ref() else {
        tracing::debug!("skipping uxarion telemetry send because endpoint is missing");
        return;
    };
    let Some(install_id) = load_or_create_install_id(runtime).await else {
        tracing::warn!("failed to resolve uxarion install id");
        return;
    };

    let event = match job {
        UxarionTelemetryJob::AppOpened => UxarionTelemetryEvent {
            event_name: "app_opened",
            install_id,
            app_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            install_channel: detect_install_channel_from_env(),
            sent_at: chrono::Utc::now().timestamp(),
            properties: json!({}),
        },
        UxarionTelemetryJob::SessionStarted(event) => UxarionTelemetryEvent {
            event_name: "session_started",
            install_id,
            app_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            install_channel: detect_install_channel_from_env(),
            sent_at: chrono::Utc::now().timestamp(),
            properties: json!({
                "providerId": event.provider_id,
                "providerName": event.provider_name,
                "providerKind": provider_kind(event.provider_id.as_str()),
                "sessionSource": event.session_source.to_string(),
                "activeProfile": event.active_profile,
                "securityModeEnabled": event.security_mode_enabled,
            }),
        },
        UxarionTelemetryJob::ReportGenerated(event) => UxarionTelemetryEvent {
            event_name: "report_generated",
            install_id,
            app_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            install_channel: detect_install_channel_from_env(),
            sent_at: chrono::Utc::now().timestamp(),
            properties: json!({
                "reportKind": event.kind.as_str(),
                "findingScoped": event.finding_scoped,
                "includeEvidence": event.include_evidence,
            }),
        },
    };

    let request = UxarionTelemetryRequest {
        events: vec![event],
    };
    match runtime
        .client
        .post(endpoint)
        .timeout(UXARION_TELEMETRY_TIMEOUT)
        .json(&request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            tracing::debug!(status = %response.status(), "uxarion telemetry event sent");
        }
        Ok(response) => {
            tracing::warn!(
                "uxarion telemetry endpoint returned status {}",
                response.status()
            );
        }
        Err(err) => {
            tracing::warn!("failed to send uxarion telemetry event: {err}");
        }
    }
}

async fn load_or_create_install_id(runtime: &UxarionTelemetryRuntime) -> Option<String> {
    let mut guard = runtime.install_id.lock().await;
    if let Some(existing) = guard.as_ref() {
        return Some(existing.clone());
    }

    let path = install_id_path(runtime.config.codex_home.as_path());
    if let Ok(existing) = fs::read_to_string(&path).await {
        let existing = existing.trim();
        if !existing.is_empty() {
            let existing = existing.to_string();
            *guard = Some(existing.clone());
            return Some(existing);
        }
    }

    let Some(parent) = path.parent() else {
        return None;
    };
    if let Err(err) = fs::create_dir_all(parent).await {
        tracing::warn!("failed to create uxarion telemetry directory: {err}");
        return None;
    }

    let install_id = Uuid::new_v4().to_string();
    if let Err(err) = fs::write(&path, &install_id).await {
        tracing::warn!("failed to persist uxarion install id: {err}");
        return None;
    }
    tracing::debug!(path = %path.display(), "persisted uxarion install id");
    *guard = Some(install_id.clone());
    Some(install_id)
}

fn install_id_path(codex_home: &Path) -> PathBuf {
    codex_home.join("telemetry").join("install_id")
}

fn detect_install_channel_from_env() -> &'static str {
    detect_install_channel(
        std::env::var_os(UXARION_MANAGED_BY_BUN_ENV_VAR).is_some(),
        std::env::var_os(UXARION_MANAGED_BY_NPM_ENV_VAR).is_some(),
    )
}

fn detect_install_channel(managed_by_bun: bool, managed_by_npm: bool) -> &'static str {
    if managed_by_bun {
        "bun"
    } else if managed_by_npm {
        "npm"
    } else {
        "direct"
    }
}

fn provider_kind(provider_id: &str) -> &'static str {
    match provider_id {
        "openai" => "api",
        "ollama" | "lmstudio" | "pentest-local" => "local",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigBuilder;
    use crate::config::types::UxarionTelemetryConfigToml;
    use codex_config::CONFIG_TOML_FILE;
    use tempfile::tempdir;

    #[test]
    fn telemetry_config_defaults_disabled_without_endpoint() {
        let config = UxarionTelemetryConfigToml::default().resolved(None);
        assert_eq!(
            config,
            UxarionTelemetryConfig {
                enabled: false,
                endpoint: None,
            }
        );
    }

    #[test]
    fn telemetry_config_requires_endpoint_and_respects_global_opt_out() {
        let enabled = UxarionTelemetryConfigToml {
            enabled: Some(true),
            endpoint: Some(" https://example.com/telemetry/events ".to_string()),
        }
        .resolved(None);
        assert_eq!(
            enabled,
            UxarionTelemetryConfig {
                enabled: true,
                endpoint: Some("https://example.com/telemetry/events".to_string()),
            }
        );

        let disabled = UxarionTelemetryConfigToml {
            enabled: Some(true),
            endpoint: Some("https://example.com/telemetry/events".to_string()),
        }
        .resolved(Some(false));
        assert_eq!(
            disabled,
            UxarionTelemetryConfig {
                enabled: false,
                endpoint: Some("https://example.com/telemetry/events".to_string()),
            }
        );
    }

    #[test]
    fn install_channel_prefers_bun_over_npm() {
        assert_eq!(detect_install_channel(true, true), "bun");
        assert_eq!(detect_install_channel(false, true), "npm");
        assert_eq!(detect_install_channel(false, false), "direct");
    }

    #[tokio::test]
    async fn install_id_is_persisted_and_reused() {
        let temp = tempdir().expect("tempdir");
        let path = install_id_path(temp.path());

        let first = {
            let parent = path.parent().expect("parent");
            fs::create_dir_all(parent)
                .await
                .expect("create telemetry dir");
            let install_id = Uuid::new_v4().to_string();
            fs::write(&path, &install_id)
                .await
                .expect("write install id");
            install_id
        };

        let second = fs::read_to_string(&path).await.expect("read install id");
        assert_eq!(second, first);
    }

    #[tokio::test]
    async fn resolved_telemetry_settings_are_loaded_from_config_file() {
        let temp = tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join(CONFIG_TOML_FILE),
            r#"[analytics]
enabled = true

[uxarion_telemetry]
enabled = true
endpoint = "https://example.com/telemetry/events"
"#,
        )
        .expect("write config");

        let config = ConfigBuilder::default()
            .codex_home(temp.path().to_path_buf())
            .fallback_cwd(Some(temp.path().to_path_buf()))
            .build()
            .await
            .expect("load config");

        assert_eq!(
            config.uxarion_telemetry,
            UxarionTelemetryConfig {
                enabled: true,
                endpoint: Some("https://example.com/telemetry/events".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn track_app_opened_creates_install_id() {
        let temp = tempdir().expect("tempdir");
        std::fs::write(
            temp.path().join(CONFIG_TOML_FILE),
            r#"[analytics]
enabled = true

[uxarion_telemetry]
enabled = true
endpoint = "http://127.0.0.1:9/telemetry/events"
"#,
        )
        .expect("write config");

        let config = Arc::new(
            ConfigBuilder::default()
                .codex_home(temp.path().to_path_buf())
                .fallback_cwd(Some(temp.path().to_path_buf()))
                .build()
                .await
                .expect("load config"),
        );

        UxarionTelemetryClient::new(config).track_app_opened();

        let install_id_path = install_id_path(temp.path());
        for _ in 0..20 {
            if install_id_path.exists() {
                let install_id =
                    std::fs::read_to_string(&install_id_path).expect("read install id");
                assert_eq!(Uuid::parse_str(install_id.trim()).is_ok(), true);
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        panic!(
            "telemetry client did not create install id at {}",
            install_id_path.display()
        );
    }
}
