use crate::config::Config;
use crate::config::types::SecurityZapConfig;
use crate::contextual_user_message::is_contextual_user_fragment;
use crate::default_client::build_reqwest_client;
use crate::function_tool::FunctionCallError;
use crate::model_provider_info::PENTEST_LOCAL_PROVIDER_ID;
use crate::tools::context::FunctionToolOutput;
use codex_protocol::ThreadId;
use codex_protocol::models::ContentItem;
use codex_protocol::models::ResponseItem;
use codex_protocol::user_input::UserInput;
use regex_lite::Regex;
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::LazyLock;
use tokio::fs;
use tokio::sync::Mutex;
use url::Url;

mod inventory;
mod zap;

pub(crate) use inventory::SecurityToolInventory;
pub(crate) use zap::ZapApiStatus;
pub(crate) use zap::resolve_zap_config;

pub(crate) const SECURITY_PROFILE_NAME: &str = "security";
pub(crate) const SECURITY_CONTEXT_OPEN_TAG: &str = "<security_context>";
pub(crate) const SECURITY_CONTEXT_CLOSE_TAG: &str = "</security_context>";
pub(crate) const SECURITY_TOOL_INVENTORY_OPEN_TAG: &str = "<security_tool_inventory>";
pub(crate) const SECURITY_TOOL_INVENTORY_CLOSE_TAG: &str = "</security_tool_inventory>";

const SECURITY_BASE_INSTRUCTIONS: &str = include_str!("../../security_prompt.md");
const SECURITY_COMPACT_PROMPT: &str = include_str!("../../security_compact_prompt.md");
const SECURITY_COLLABORATION_INSTRUCTIONS: &str = include_str!("../../security_collaboration.md");

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"https?://[^\s"'<>]+"#).expect("security URL regex should compile")
});
static HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b"#)
        .expect("security host regex should compile")
});
static IPV4_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#).expect("security ipv4 regex should compile")
});

pub(crate) const SECURITY_BINARY_ALLOWLIST: &[&str] = &[
    "amass",
    "awk",
    "bash",
    "curl",
    "dig",
    "ffuf",
    "grep",
    "host",
    "httpx",
    "jq",
    "nmap",
    "nslookup",
    "nuclei",
    "openssl",
    "python3",
    "sed",
    "sh",
    "subfinder",
    "tee",
    "wget",
    "whatweb",
    "zap-baseline.py",
    "zap-full-scan.py",
    "zap.sh",
    "zaproxy",
];

static DISALLOWED_COMMAND_PATTERNS: &[&str] = &[
    " --flood",
    " DROP TABLE ",
    "&& rm ",
    "mkfs",
    "poweroff",
    "reboot",
    "shutdown",
    "slowloris",
];

static LOCAL_FILESYSTEM_EXPLORATION_BINARIES: &[&str] = &[
    "awk", "cat", "find", "grep", "head", "jq", "ls", "pwd", "readlink", "realpath", "rg", "sed",
    "stat", "tail", "tee", "wc",
];

static LOCAL_ARTIFACT_READ_ONLY_BINARIES: &[&str] = &[
    "awk", "grep", "head", "jq", "readlink", "realpath", "sed", "stat", "tail", "wc",
];

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SecurityScope {
    pub mode: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub notes: Option<String>,
    pub derived_from: Option<String>,
}

impl SecurityScope {
    pub(crate) fn has_targets(&self) -> bool {
        !self.allowed_hosts.is_empty() || !self.allowed_domains.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RecordedRequest {
    pub url: String,
    pub method: String,
    pub headers: BTreeMap<String, String>,
    pub body_preview: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RecordedResponse {
    pub url: String,
    pub status: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub body_preview: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct EvidenceRecord {
    pub id: String,
    pub name: String,
    pub path: String,
    pub source: Option<String>,
    pub media_type: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct FindingRecord {
    #[serde(default)]
    pub id: String,
    pub target: String,
    pub vulnerability: String,
    pub severity: String,
    pub confidence: String,
    pub evidence: Vec<String>,
    pub reproduction: Option<String>,
    pub impact: Option<String>,
    pub limitations: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct ExecutedCommandRecord {
    pub cmd: String,
    pub purpose: String,
    pub exit_code: Option<i32>,
    pub output_preview: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SecuritySessionState {
    pub scope: SecurityScope,
    pub targets: Vec<String>,
    pub urls: Vec<String>,
    pub requests: Vec<RecordedRequest>,
    pub responses: Vec<RecordedResponse>,
    pub auth_state: Option<String>,
    pub evidence_index: Vec<EvidenceRecord>,
    pub findings: Vec<FindingRecord>,
    #[serde(default)]
    pub commands: Vec<ExecutedCommandRecord>,
}

pub(crate) fn is_security_config(config: &Config) -> bool {
    config.active_profile.as_deref() == Some(SECURITY_PROFILE_NAME)
        || config.model_provider_id == PENTEST_LOCAL_PROVIDER_ID
}

pub(crate) fn apply_runtime_overrides(config: &mut Config) {
    if !is_security_config(config) {
        return;
    }

    if config.base_instructions.is_none() {
        config.base_instructions = Some(SECURITY_BASE_INSTRUCTIONS.to_string());
    }

    if config.compact_prompt.is_none() {
        config.compact_prompt = Some(SECURITY_COMPACT_PROMPT.to_string());
    }
}

pub(crate) fn collaboration_instructions() -> &'static str {
    SECURITY_COLLABORATION_INSTRUCTIONS
}

pub(crate) struct SecuritySessionStateService {
    enabled: bool,
    root_dir: PathBuf,
    evidence_dir: PathBuf,
    state_path: PathBuf,
    findings_path: PathBuf,
    report_path: PathBuf,
    zap_config: SecurityZapConfig,
    inventory: SecurityToolInventory,
    state: Mutex<SecuritySessionState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecurityArtifactPaths {
    pub root_dir: PathBuf,
    pub evidence_dir: PathBuf,
    pub state_path: PathBuf,
    pub findings_path: PathBuf,
    pub report_path: PathBuf,
}

impl SecuritySessionStateService {
    pub(crate) async fn new(
        codex_home: &Path,
        thread_id: &ThreadId,
        enabled: bool,
        zap_config: SecurityZapConfig,
    ) -> Self {
        let root_dir = codex_home.join("security").join(thread_id.to_string());
        let evidence_dir = root_dir.join("evidence");
        let state_path = root_dir.join("state.json");
        let findings_path = root_dir.join("findings.json");
        let report_path = root_dir.join("report.md");
        let inventory = if enabled {
            SecurityToolInventory::discover(&zap_config).await
        } else {
            SecurityToolInventory::disabled(&zap_config)
        };

        let initial_state = if enabled {
            if let Err(err) = fs::create_dir_all(&evidence_dir).await {
                tracing::warn!("failed to create security evidence dir: {err}");
            }
            load_state_from_disk(&state_path, &findings_path)
                .await
                .unwrap_or_default()
        } else {
            SecuritySessionState::default()
        };

        Self {
            enabled,
            root_dir,
            evidence_dir,
            state_path,
            findings_path,
            report_path,
            zap_config,
            inventory,
            state: Mutex::new(initial_state),
        }
    }

    pub(crate) async fn render_context_fragment(&self, history: &[ResponseItem]) -> Option<String> {
        if !self.enabled {
            return None;
        }

        self.ensure_default_scope_from_history(history).await;
        let snapshot = self.snapshot().await;
        let body = serde_json::to_string_pretty(&json!({
            "scope": snapshot.scope,
            "targets": snapshot.targets,
            "urls": snapshot.urls,
            "auth_state": snapshot.auth_state,
            "evidence_count": snapshot.evidence_index.len(),
            "finding_count": snapshot.findings.len(),
            "recent_commands": snapshot.commands.into_iter().rev().take(5).collect::<Vec<_>>(),
            "latest_findings": snapshot.findings.into_iter().rev().take(3).collect::<Vec<_>>(),
        }))
        .unwrap_or_else(|_| "{}".to_string());
        Some(body)
    }

    pub(crate) fn artifact_paths(&self) -> SecurityArtifactPaths {
        SecurityArtifactPaths {
            root_dir: self.root_dir.clone(),
            evidence_dir: self.evidence_dir.clone(),
            state_path: self.state_path.clone(),
            findings_path: self.findings_path.clone(),
            report_path: self.report_path.clone(),
        }
    }

    pub(crate) fn render_tool_inventory_fragment(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }

        serde_json::to_string_pretty(&self.inventory).ok()
    }

    pub(crate) fn zap_config(&self) -> &SecurityZapConfig {
        &self.zap_config
    }

    pub(crate) async fn zap_status(&self) -> ZapApiStatus {
        zap::probe_zap_api(&self.zap_config).await
    }

    pub(crate) async fn snapshot(&self) -> SecuritySessionState {
        self.state.lock().await.clone()
    }

    pub(crate) async fn ensure_default_scope_from_user_input(&self, input: &[UserInput]) {
        if !self.enabled {
            return;
        }

        let mut state = self.state.lock().await;
        if state.scope.has_targets() {
            return;
        }

        let text = input
            .iter()
            .filter_map(|item| match item {
                UserInput::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n");
        if text.is_empty() {
            return;
        }

        if let Some(target) = derive_first_target_from_text(&text)
            && apply_target_to_scope(&mut state.scope, &target).is_ok()
        {
            state.scope.derived_from = Some("current_user_input".to_string());
            push_unique(&mut state.targets, target);
        }

        let snapshot = state.clone();
        drop(state);
        let _ = self.persist_state(&snapshot).await;
    }

    pub(crate) async fn validate_scope(
        &self,
        targets: &[String],
        notes: Option<String>,
        replace: bool,
    ) -> Result<SecuritySessionState, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        if targets.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "scope_validate requires at least one target".to_string(),
            ));
        }

        let mut state = self.state.lock().await;
        if replace {
            state.scope = SecurityScope {
                mode: "host_only".to_string(),
                ..SecurityScope::default()
            };
            state.targets.clear();
        }
        for target in targets {
            apply_target_to_scope(&mut state.scope, target)?;
            push_unique(&mut state.targets, target.to_string());
        }
        if notes.is_some() {
            state.scope.notes = notes;
        }
        let snapshot = state.clone();
        drop(state);
        self.persist_state(&snapshot).await?;
        Ok(snapshot)
    }

    pub(crate) async fn ensure_url_in_scope(&self, url: &str) -> Result<(), FunctionCallError> {
        if !self.enabled {
            return Ok(());
        }
        let host = parse_host(url)?;
        let state = self.state.lock().await;
        if !scope_allows_host(&state.scope, &host) {
            return Err(FunctionCallError::RespondToModel(format!(
                "target `{host}` is outside the current security scope; update scope explicitly before testing it"
            )));
        }

        let exact_targets = exact_url_targets(&state.targets);
        if !exact_targets.is_empty() && !exact_targets.iter().any(|target| target.matches_url(url))
        {
            return Err(FunctionCallError::RespondToModel(format!(
                "target `{url}` is outside the current exact security scope; stay on the user-provided URL/host/port/path"
            )));
        }

        Ok(())
    }

    pub(crate) async fn ensure_targets_in_scope(
        &self,
        targets: &[String],
    ) -> Result<(), FunctionCallError> {
        if !self.enabled {
            return Ok(());
        }

        if targets.is_empty() {
            return Ok(());
        }

        let state = self.state.lock().await;
        for target in targets {
            let host = parse_host_or_literal(target)?;
            if !scope_allows_host(&state.scope, &host) {
                return Err(FunctionCallError::RespondToModel(format!(
                    "target `{host}` is outside the current security scope; update scope explicitly before testing it"
                )));
            }
        }
        Ok(())
    }

    pub(crate) async fn record_http_transaction(
        &self,
        request: RecordedRequest,
        response: RecordedResponse,
        discovered_url: Option<String>,
    ) -> Result<(), FunctionCallError> {
        if !self.enabled {
            return Ok(());
        }

        let mut state = self.state.lock().await;
        state.requests.push(request);
        state.responses.push(response);
        if let Some(url) = discovered_url {
            push_unique(&mut state.urls, url);
        }
        let snapshot = state.clone();
        drop(state);
        self.persist_state(&snapshot).await
    }

    pub(crate) async fn record_discovered_urls(
        &self,
        urls: &[String],
    ) -> Result<SecuritySessionState, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let mut state = self.state.lock().await;
        for url in urls {
            push_unique(&mut state.urls, url.clone());
        }
        let snapshot = state.clone();
        drop(state);
        self.persist_state(&snapshot).await?;
        Ok(snapshot)
    }

    pub(crate) async fn capture_text_evidence(
        &self,
        name: &str,
        content: &str,
        media_type: Option<String>,
        notes: Option<String>,
        source: Option<String>,
    ) -> Result<EvidenceRecord, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let evidence_id = sanitize_identifier(name);
        let evidence_path = self.evidence_dir.join(format!("{evidence_id}.txt"));
        fs::write(&evidence_path, content).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to write evidence: {err}"))
        })?;

        let record = EvidenceRecord {
            id: evidence_id,
            name: name.to_string(),
            path: evidence_path.to_string_lossy().into_owned(),
            source,
            media_type,
            notes,
        };
        self.record_evidence_record(record.clone()).await?;
        Ok(record)
    }

    pub(crate) async fn capture_file_evidence(
        &self,
        name: &str,
        source_path: &Path,
        media_type: Option<String>,
        notes: Option<String>,
        source: Option<String>,
    ) -> Result<Option<EvidenceRecord>, FunctionCallError> {
        if !self.enabled {
            return Ok(None);
        }

        let metadata = fs::metadata(source_path).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to read artifact metadata for `{}`: {err}",
                source_path.display()
            ))
        })?;
        if !metadata.is_file() {
            return Ok(None);
        }

        let file_name = source_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact");
        let evidence_id = sanitize_identifier(name);
        let destination = self.evidence_dir.join(format!("{evidence_id}_{file_name}"));
        fs::copy(source_path, &destination).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to copy evidence artifact: {err}"))
        })?;

        let record = EvidenceRecord {
            id: evidence_id,
            name: name.to_string(),
            path: destination.to_string_lossy().into_owned(),
            source,
            media_type,
            notes,
        };
        self.record_evidence_record(record.clone()).await?;
        Ok(Some(record))
    }

    pub(crate) async fn record_finding(
        &self,
        mut finding: FindingRecord,
    ) -> Result<SecuritySessionState, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let mut state = self.state.lock().await;
        if finding.id.trim().is_empty() {
            finding.id = next_finding_id(&state.findings);
        }
        state.findings.push(finding);
        let snapshot = state.clone();
        drop(state);
        self.persist_state(&snapshot).await?;
        Ok(snapshot)
    }

    pub(crate) async fn record_command(
        &self,
        command: ExecutedCommandRecord,
    ) -> Result<SecuritySessionState, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let mut state = self.state.lock().await;
        state.commands.push(command);
        if state.commands.len() > 25 {
            let drain_count = state.commands.len().saturating_sub(25);
            state.commands.drain(0..drain_count);
        }
        let snapshot = state.clone();
        drop(state);
        self.persist_state(&snapshot).await?;
        Ok(snapshot)
    }

    pub(crate) async fn write_report(
        &self,
        summary: Option<&str>,
        include_evidence: bool,
        finding_id: Option<&str>,
    ) -> Result<PathBuf, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let mut snapshot = self.snapshot().await;
        snapshot.findings.sort_by(|a, b| {
            (&a.target, &a.vulnerability, &a.severity).cmp(&(
                &b.target,
                &b.vulnerability,
                &b.severity,
            ))
        });

        if let Some(finding_id) = finding_id {
            let finding_id = finding_id.trim();
            if finding_id.is_empty() {
                return Err(FunctionCallError::RespondToModel(
                    "`finding_id` must not be empty".to_string(),
                ));
            }

            let selected = snapshot
                .findings
                .iter()
                .find(|finding| finding.id == finding_id)
                .cloned()
                .ok_or_else(|| {
                    FunctionCallError::RespondToModel(format!(
                        "finding `{finding_id}` was not found"
                    ))
                })?;

            snapshot.findings = vec![selected];
            let report = render_report_markdown(&snapshot, summary, include_evidence);
            let report_path = finding_report_path(&self.root_dir, finding_id);
            fs::write(&report_path, report).await.map_err(|err| {
                FunctionCallError::RespondToModel(format!(
                    "failed to write finding report for `{finding_id}`: {err}"
                ))
            })?;
            return Ok(report_path);
        }

        let report = render_report_markdown(&snapshot, summary, include_evidence);
        fs::write(&self.report_path, report).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to write security report: {err}"))
        })?;
        Ok(self.report_path.clone())
    }

    pub(crate) async fn save_report_markdown(
        &self,
        content: &str,
        finding_id: Option<&str>,
    ) -> Result<PathBuf, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let content = content.trim();
        if content.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "`content` must not be empty".to_string(),
            ));
        }

        let report_path = if let Some(finding_id) = finding_id {
            let finding_id = finding_id.trim();
            if finding_id.is_empty() {
                return Err(FunctionCallError::RespondToModel(
                    "`finding_id` must not be empty".to_string(),
                ));
            }

            let snapshot = self.snapshot().await;
            if !snapshot
                .findings
                .iter()
                .any(|finding| finding.id == finding_id)
            {
                return Err(FunctionCallError::RespondToModel(format!(
                    "finding `{finding_id}` was not found"
                )));
            }

            finding_report_path(&self.root_dir, finding_id)
        } else {
            self.report_path.clone()
        };

        let normalized = if content.ends_with('\n') {
            content.to_string()
        } else {
            format!("{content}\n")
        };

        fs::write(&report_path, normalized).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to write security report: {err}"))
        })?;

        Ok(report_path)
    }

    pub(crate) async fn capture_expected_artifacts(
        &self,
        workdir: &Path,
        artifact_paths: &[String],
    ) -> Result<Vec<EvidenceRecord>, FunctionCallError> {
        let mut captured = Vec::new();
        for artifact in artifact_paths {
            let path = if Path::new(artifact).is_absolute() {
                PathBuf::from(artifact)
            } else {
                workdir.join(artifact)
            };
            if !path.exists() {
                continue;
            }
            if let Some(record) = self
                .capture_file_evidence(
                    artifact,
                    &path,
                    None,
                    Some("captured from security_exec expected_artifacts".to_string()),
                    Some("security_exec".to_string()),
                )
                .await?
            {
                captured.push(record);
            }
        }
        Ok(captured)
    }

    pub(crate) async fn http_inspect(
        &self,
        url: &str,
        method: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&str>,
        capture_body: bool,
        max_body_bytes: usize,
    ) -> Result<FunctionToolOutput, FunctionCallError> {
        self.ensure_url_in_scope(url).await?;

        let method = method.to_ascii_uppercase();
        let parsed_method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|err| {
            FunctionCallError::RespondToModel(format!("invalid HTTP method `{method}`: {err}"))
        })?;

        let client = build_reqwest_client();
        let mut request = client.request(parsed_method.clone(), url);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("HTTP inspection failed: {err}"))
        })?;

        let status = response.status().as_u16();
        let final_url = response.url().to_string();
        self.ensure_url_in_scope(&final_url).await?;

        let mut response_headers = BTreeMap::new();
        for (name, value) in response.headers() {
            response_headers.insert(
                name.to_string(),
                value.to_str().unwrap_or_default().to_string(),
            );
        }
        let bytes = response.bytes().await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to read HTTP response body: {err}"))
        })?;
        let body_preview =
            String::from_utf8_lossy(&bytes[..bytes.len().min(max_body_bytes)]).to_string();
        let title = extract_html_title(&body_preview);
        let forms = extract_form_summaries(&body_preview);

        self.record_http_transaction(
            RecordedRequest {
                url: url.to_string(),
                method,
                headers: headers.clone(),
                body_preview: body.map(|value| value.chars().take(500).collect()),
            },
            RecordedResponse {
                url: final_url.clone(),
                status: Some(status),
                headers: response_headers.clone(),
                body_preview: capture_body.then_some(body_preview.clone()),
            },
            Some(final_url.clone()),
        )
        .await?;

        let evidence = if capture_body {
            Some(
                self.capture_text_evidence(
                    "http_inspect_response",
                    &body_preview,
                    response_headers.get("content-type").cloned(),
                    Some(format!("Captured from {final_url}")),
                    Some(final_url.clone()),
                )
                .await?,
            )
        } else {
            None
        };

        let output = json!({
            "url": final_url,
            "status": status,
            "headers": response_headers,
            "title": title,
            "forms": forms,
            "body_captured": evidence.as_ref().map(|record| record.path.clone()),
        });

        Ok(FunctionToolOutput::from_text(
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| output.to_string()),
            Some(true),
        ))
    }

    async fn ensure_default_scope_from_history(&self, history: &[ResponseItem]) {
        if !self.enabled {
            return;
        }

        let mut state = self.state.lock().await;
        if state.scope.has_targets() {
            return;
        }

        for item in history {
            let ResponseItem::Message { role, content, .. } = item else {
                continue;
            };
            if role != "user" {
                continue;
            }

            let text = message_text(content);
            if text.is_empty() {
                continue;
            }

            if let Some(target) = derive_first_target_from_text(&text)
                && apply_target_to_scope(&mut state.scope, &target).is_ok()
            {
                state.scope.derived_from = Some("conversation_history".to_string());
                push_unique(&mut state.targets, target);
                break;
            }
        }

        let snapshot = state.clone();
        drop(state);
        let _ = self.persist_state(&snapshot).await;
    }

    async fn record_evidence_record(
        &self,
        record: EvidenceRecord,
    ) -> Result<(), FunctionCallError> {
        let mut state = self.state.lock().await;
        state.evidence_index.push(record);
        let snapshot = state.clone();
        drop(state);
        self.persist_state(&snapshot).await
    }

    async fn persist_state(&self, state: &SecuritySessionState) -> Result<(), FunctionCallError> {
        if !self.enabled {
            return Ok(());
        }

        fs::create_dir_all(&self.root_dir).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to prepare security state dir: {err}"
            ))
        })?;
        let serialized_state = serde_json::to_vec_pretty(state).map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to serialize security state: {err}"))
        })?;
        fs::write(&self.state_path, serialized_state)
            .await
            .map_err(|err| {
                FunctionCallError::RespondToModel(format!(
                    "failed to persist security state: {err}"
                ))
            })?;
        let serialized_findings = serde_json::to_vec_pretty(&state.findings).map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to serialize security findings: {err}"
            ))
        })?;
        fs::write(&self.findings_path, serialized_findings)
            .await
            .map_err(|err| {
                FunctionCallError::RespondToModel(format!(
                    "failed to persist security findings: {err}"
                ))
            })?;
        Ok(())
    }
}

async fn load_state_from_disk(
    state_path: &Path,
    findings_path: &Path,
) -> Option<SecuritySessionState> {
    let mut state: SecuritySessionState = match fs::read(state_path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).ok()?,
        Err(_) => SecuritySessionState::default(),
    };

    if let Ok(bytes) = fs::read(findings_path).await
        && let Ok(findings) = serde_json::from_slice::<Vec<FindingRecord>>(&bytes)
    {
        state.findings = findings;
    }
    ensure_finding_ids(&mut state.findings);
    Some(state)
}

fn next_finding_id(findings: &[FindingRecord]) -> String {
    let mut next = 1usize;
    while findings
        .iter()
        .any(|finding| finding.id == format!("finding-{next:04}"))
    {
        next += 1;
    }
    format!("finding-{next:04}")
}

fn ensure_finding_ids(findings: &mut [FindingRecord]) {
    for index in 0..findings.len() {
        if findings[index].id.trim().is_empty() {
            findings[index].id = next_finding_id(&findings[..index]);
        }
    }
}

fn finding_report_path(root_dir: &Path, finding_id: &str) -> PathBuf {
    root_dir.join(format!(
        "report-finding-{}.md",
        sanitize_identifier(finding_id)
    ))
}

fn message_text(content: &[ContentItem]) -> String {
    content
        .iter()
        .filter_map(|item| {
            if is_contextual_user_fragment(item) {
                return None;
            }
            match item {
                ContentItem::InputText { text } | ContentItem::OutputText { text } => {
                    Some(text.as_str())
                }
                ContentItem::InputImage { .. } => None,
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn derive_first_target_from_text(text: &str) -> Option<String> {
    URL_REGEX
        .find(text)
        .map(|match_| {
            match_
                .as_str()
                .trim_end_matches(['.', ',', ';'])
                .to_string()
        })
        .or_else(|| {
            HOST_REGEX
                .find(text)
                .map(|match_| match_.as_str().to_string())
        })
        .or_else(|| {
            IPV4_REGEX
                .find(text)
                .map(|match_| match_.as_str().to_string())
        })
}

fn apply_target_to_scope(scope: &mut SecurityScope, target: &str) -> Result<(), FunctionCallError> {
    let normalized = target.trim();
    if normalized.is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "scope target cannot be empty".to_string(),
        ));
    }

    if is_local_path_like(normalized) {
        return Err(FunctionCallError::RespondToModel(
            "scope_validate does not accept local file paths; read the provided artifacts directly instead"
                .to_string(),
        ));
    }

    if normalized.starts_with("*.") {
        let domain = normalized
            .trim_start_matches("*.")
            .trim()
            .to_ascii_lowercase();
        if domain.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "invalid wildcard target".to_string(),
            ));
        }
        scope.mode = "domain".to_string();
        push_unique(&mut scope.allowed_domains, domain);
        return Ok(());
    }

    let host = parse_host_or_literal(normalized)?;
    scope.mode = "host_only".to_string();
    push_unique(&mut scope.allowed_hosts, host);
    Ok(())
}

fn parse_host(input: &str) -> Result<String, FunctionCallError> {
    let parsed = Url::parse(input).map_err(|err| {
        FunctionCallError::RespondToModel(format!("invalid URL `{input}`: {err}"))
    })?;
    url_host_with_port(&parsed).ok_or_else(|| {
        FunctionCallError::RespondToModel(format!("URL `{input}` does not include a valid host"))
    })
}

fn parse_host_or_literal(input: &str) -> Result<String, FunctionCallError> {
    if input.contains("://") {
        return parse_host(input);
    }
    Ok(input.trim().trim_matches('/').to_ascii_lowercase())
}

fn is_local_path_like(input: &str) -> bool {
    let trimmed = input.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with("~/")
        || trimmed.starts_with("file://")
}

pub(crate) fn scope_allows_host(scope: &SecurityScope, host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    if scope.allowed_hosts.iter().any(|entry| entry == &normalized) {
        return true;
    }

    let domain_host = host_without_port(&normalized);
    scope
        .allowed_domains
        .iter()
        .any(|domain| domain_host == *domain || domain_host.ends_with(&format!(".{domain}")))
}

pub(crate) fn command_is_allowed(
    command_words: &[Vec<String>],
    scope_targets: &[String],
    allowed_local_paths: &[String],
    current_targets: &[String],
    current_scope: &SecurityScope,
    artifact_paths: &SecurityArtifactPaths,
) -> Result<(), FunctionCallError> {
    if command_words.is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "security_exec requires a concrete command".to_string(),
        ));
    }

    let exact_targets = exact_url_targets(current_targets);
    for command in command_words {
        let Some(binary) = command.first() else {
            continue;
        };
        if !SECURITY_BINARY_ALLOWLIST.contains(&binary.as_str()) {
            return Err(FunctionCallError::RespondToModel(format!(
                "binary `{binary}` is not allowed in security mode"
            )));
        }
        if matches!(binary.as_str(), "bash" | "sh") {
            return Err(FunctionCallError::RespondToModel(
                "nested shells are not allowed in security_exec; pass the final command directly"
                    .to_string(),
            ));
        }
        if binary == "python3" && scope_targets.is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "python3 commands require explicit `scope_targets` because their network targets cannot be inferred safely"
                    .to_string(),
            ));
        }
        let mut saw_allowed_local_path = false;
        let mut touched_security_artifact_path = false;
        for token in command {
            if !exact_targets.is_empty()
                && let Ok(parsed) =
                    Url::parse(token.trim().trim_matches(|ch| matches!(ch, '"' | '\'')))
                && matches!(parsed.scheme(), "http" | "https")
                && !exact_targets
                    .iter()
                    .any(|target| target.matches_parsed_url(&parsed))
            {
                return Err(FunctionCallError::RespondToModel(format!(
                    "command target `{}` is outside the current exact security scope",
                    token.trim().trim_matches(|ch| matches!(ch, '"' | '\''))
                )));
            }
            if let Some(host) = maybe_extract_host_from_token(token)
                && !scope_allows_host(current_scope, &host)
            {
                return Err(FunctionCallError::RespondToModel(format!(
                    "command target `{host}` is outside the current security scope"
                )));
            }
            if let Some(local_path) = normalize_local_path_token(token) {
                if !local_path_is_allowed(&local_path, allowed_local_paths) {
                    return Err(FunctionCallError::RespondToModel(format!(
                        "local path `{local_path}` is outside the allowed security artifact paths for this command"
                    )));
                }
                saw_allowed_local_path = true;
                if local_path_references_security_artifacts(&local_path, artifact_paths) {
                    touched_security_artifact_path = true;
                }
            }
        }
        if touched_security_artifact_path
            && !LOCAL_ARTIFACT_READ_ONLY_BINARIES.contains(&binary.as_str())
        {
            return Err(FunctionCallError::RespondToModel(
                "security session artifacts must be written only through `capture_evidence`, `record_finding`, and `report_write`; do not fabricate them with shell commands".to_string(),
            ));
        }
        if LOCAL_FILESYSTEM_EXPLORATION_BINARIES.contains(&binary.as_str())
            && !allowed_local_paths.is_empty()
            && !saw_allowed_local_path
        {
            return Err(FunctionCallError::RespondToModel(format!(
                "binary `{binary}` must stay on the explicitly allowed security artifact paths for this command"
            )));
        }
        if !allowed_local_paths.is_empty()
            && !LOCAL_ARTIFACT_READ_ONLY_BINARIES.contains(&binary.as_str())
        {
            return Err(FunctionCallError::RespondToModel(format!(
                "binary `{binary}` is not allowed for report or artifact inspection; use direct read-only tools on the provided paths only"
            )));
        }
    }

    for target in scope_targets {
        if is_local_path_like(target) {
            continue;
        }
        let host = parse_host_or_literal(target)?;
        if !scope_allows_host(current_scope, &host) {
            return Err(FunctionCallError::RespondToModel(format!(
                "declared scope target `{host}` is outside the current security scope"
            )));
        }
    }

    Ok(())
}

pub(crate) fn maybe_extract_host_from_token(token: &str) -> Option<String> {
    let normalized = token.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if normalized.starts_with('-') || is_local_path_like(normalized) {
        return None;
    }
    if let Ok(parsed) = Url::parse(normalized) {
        if parsed.scheme() == "file" {
            return None;
        }
        return url_host_with_port(&parsed);
    }
    if HOST_REGEX.is_match(normalized) || IPV4_REGEX.is_match(normalized) {
        return Some(normalized.trim_matches('/').to_ascii_lowercase());
    }
    None
}

fn normalize_local_path_token(token: &str) -> Option<String> {
    let normalized = token.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    if let Some(path) = normalized.strip_prefix("file://") {
        return Some(path.to_string());
    }
    if normalized.starts_with('/') {
        return Some(normalized.to_string());
    }
    None
}

fn local_path_is_allowed(path: &str, allowed_local_paths: &[String]) -> bool {
    let candidate = Path::new(path);
    allowed_local_paths.iter().any(|allowed| {
        let allowed_path = Path::new(allowed);
        candidate == allowed_path || candidate.starts_with(allowed_path)
    })
}

fn local_path_references_security_artifacts(
    path: &str,
    artifact_paths: &SecurityArtifactPaths,
) -> bool {
    let candidate = Path::new(path);
    candidate == artifact_paths.state_path
        || candidate == artifact_paths.findings_path
        || candidate == artifact_paths.report_path
        || candidate == artifact_paths.evidence_dir
        || candidate.starts_with(&artifact_paths.evidence_dir)
        || candidate.starts_with(&artifact_paths.root_dir)
}

pub(crate) fn generic_exec_command_security_violation(
    cmd: &str,
    artifact_paths: &SecurityArtifactPaths,
) -> Option<String> {
    let lowered = cmd.to_ascii_lowercase();
    let root_dir = artifact_paths
        .root_dir
        .to_string_lossy()
        .to_ascii_lowercase();
    let evidence_dir = artifact_paths
        .evidence_dir
        .to_string_lossy()
        .to_ascii_lowercase();
    let state_path = artifact_paths
        .state_path
        .to_string_lossy()
        .to_ascii_lowercase();
    let findings_path = artifact_paths
        .findings_path
        .to_string_lossy()
        .to_ascii_lowercase();
    let report_path = artifact_paths
        .report_path
        .to_string_lossy()
        .to_ascii_lowercase();
    let security_root = artifact_paths
        .root_dir
        .parent()
        .map(|path| path.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();

    let touches_exact_artifact_paths = [
        root_dir.as_str(),
        evidence_dir.as_str(),
        state_path.as_str(),
        findings_path.as_str(),
        report_path.as_str(),
    ]
    .iter()
    .any(|needle| !needle.is_empty() && lowered.contains(needle));
    let mentions_artifact_names = ["findings.json", "state.json", "report.md", "evidence"]
        .iter()
        .any(|needle| lowered.contains(needle));
    let broad_search_binary = lowered.starts_with("find ")
        || lowered.starts_with("rg ")
        || lowered.starts_with("ls ")
        || lowered.contains(" grep -r")
        || lowered.starts_with("grep -r")
        || lowered.contains(" grep -r ")
        || lowered.contains(" grep -r/")
        || lowered.contains(" grep -r\t")
        || lowered.contains(" grep -r\n")
        || lowered.contains(" grep -R")
        || lowered.starts_with("grep -R");
    let broad_search_root = lowered.contains("/root")
        || lowered.contains("$home")
        || lowered.contains("~/.uxarion")
        || (!security_root.is_empty() && lowered.contains(&security_root));
    if mentions_artifact_names && broad_search_binary && broad_search_root {
        return Some(
            "exact security artifact paths are already available; do not run broad local searches across `/root`, `$HOME`, workspaces, or historical sessions".to_string(),
        );
    }

    let mutating_pattern = lowered.contains(" tee ")
        || lowered.starts_with("tee ")
        || lowered.contains(" printf ")
        || lowered.starts_with("printf ")
        || lowered.contains(" echo ")
        || lowered.starts_with("echo ")
        || lowered.contains(" mkdir ")
        || lowered.starts_with("mkdir ")
        || lowered.contains(" touch ")
        || lowered.starts_with("touch ")
        || lowered.contains(" cp ")
        || lowered.starts_with("cp ")
        || lowered.contains(" mv ")
        || lowered.starts_with("mv ")
        || lowered.contains(" install ")
        || lowered.starts_with("install ")
        || lowered.contains(" python ")
        || lowered.starts_with("python ")
        || lowered.contains(" python3 ")
        || lowered.starts_with("python3 ")
        || lowered.contains(" sed -i")
        || lowered.contains(" perl -0pi")
        || lowered.contains(">")
        || lowered.contains(">>");
    if touches_exact_artifact_paths && mutating_pattern {
        return Some(
            "security session artifacts must be written only through `capture_evidence`, `record_finding`, and `report_write`; do not fabricate them with shell commands".to_string(),
        );
    }

    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactUrlTarget {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

impl ExactUrlTarget {
    fn matches_url(&self, candidate: &str) -> bool {
        Url::parse(candidate)
            .ok()
            .is_some_and(|parsed| self.matches_parsed_url(&parsed))
    }

    fn matches_parsed_url(&self, candidate: &Url) -> bool {
        matches!(candidate.scheme(), "http" | "https")
            && candidate.scheme().eq_ignore_ascii_case(&self.scheme)
            && candidate
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(&self.host))
            && candidate.port() == self.port
            && normalize_url_path(candidate.path()) == self.path
    }
}

fn exact_url_targets(targets: &[String]) -> Vec<ExactUrlTarget> {
    targets
        .iter()
        .filter_map(|target| parse_exact_url_target(target))
        .collect()
}

fn parse_exact_url_target(input: &str) -> Option<ExactUrlTarget> {
    let parsed = Url::parse(input).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some(ExactUrlTarget {
        scheme: parsed.scheme().to_ascii_lowercase(),
        host,
        port: parsed.port(),
        path: normalize_url_path(parsed.path()),
    })
}

fn normalize_url_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    }
}

fn host_without_port(host: &str) -> &str {
    if host.matches(':').count() == 1 {
        host.split(':').next().unwrap_or(host)
    } else {
        host
    }
}

fn url_host_with_port(url: &Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

pub(crate) fn command_contains_disallowed_pattern(cmd: &str) -> Option<&'static str> {
    let lowered = format!(" {} ", cmd.to_ascii_lowercase());
    DISALLOWED_COMMAND_PATTERNS
        .iter()
        .copied()
        .find(|pattern| lowered.contains(&pattern.to_ascii_lowercase()))
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
    }
}

fn sanitize_identifier(input: &str) -> String {
    let compact = input
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>()
        .trim_matches('_')
        .to_ascii_lowercase();
    let fallback = if compact.is_empty() {
        "evidence"
    } else {
        &compact
    };
    format!(
        "{fallback}_{}",
        chrono::Utc::now().format("%Y%m%d%H%M%S%3f")
    )
}

fn extract_html_title(body: &str) -> Option<String> {
    let title_regex = Regex::new(r"(?is)<title[^>]*>(.*?)</title>").ok()?;
    title_regex
        .captures(body)
        .and_then(|captures| captures.get(1))
        .map(|title| html_unescape(title.as_str()).trim().to_string())
        .filter(|title| !title.is_empty())
}

fn extract_form_summaries(body: &str) -> Vec<serde_json::Value> {
    let form_regex = Regex::new(r#"(?is)<form(?P<attrs>[^>]*)>"#).expect("form regex");
    let action_regex = Regex::new(r#"(?i)action\s*=\s*['"]?([^'"\s>]+)"#).expect("action regex");
    let method_regex = Regex::new(r#"(?i)method\s*=\s*['"]?([^'"\s>]+)"#).expect("method regex");
    form_regex
        .captures_iter(body)
        .map(|captures| {
            let attrs = captures
                .name("attrs")
                .map(|value| value.as_str())
                .unwrap_or("");
            json!({
                "action": action_regex
                    .captures(attrs)
                    .and_then(|captures| captures.get(1))
                    .map(|value| value.as_str().to_string()),
                "method": method_regex
                    .captures(attrs)
                    .and_then(|captures| captures.get(1))
                    .map(|value| value.as_str().to_ascii_uppercase())
                    .unwrap_or_else(|| "GET".to_string()),
            })
        })
        .collect()
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

fn render_report_markdown(
    state: &SecuritySessionState,
    summary: Option<&str>,
    include_evidence: bool,
) -> String {
    let mut lines = Vec::new();
    lines.push("# Security Assessment Report".to_string());
    lines.push(String::new());
    if let Some(summary) = summary {
        lines.push(summary.to_string());
        lines.push(String::new());
    }
    lines.push("## Scope".to_string());
    lines.push(format!(
        "- Mode: {}",
        if state.scope.mode.is_empty() {
            "host_only"
        } else {
            state.scope.mode.as_str()
        }
    ));
    if !state.scope.allowed_hosts.is_empty() {
        lines.push(format!(
            "- Allowed hosts: {}",
            state.scope.allowed_hosts.join(", ")
        ));
    }
    if !state.scope.allowed_domains.is_empty() {
        lines.push(format!(
            "- Allowed domains: {}",
            state.scope.allowed_domains.join(", ")
        ));
    }
    if let Some(notes) = &state.scope.notes {
        lines.push(format!("- Notes: {notes}"));
    }
    lines.push(String::new());
    lines.push("## Findings".to_string());
    if state.findings.is_empty() {
        lines.push("- No confirmed findings recorded.".to_string());
    } else {
        for finding in &state.findings {
            lines.push(format!(
                "- [{}] {} on {} [{} / {} / {}]",
                finding.id,
                finding.vulnerability,
                finding.target,
                finding.severity,
                finding.confidence,
                finding.status
            ));
            if let Some(impact) = &finding.impact {
                lines.push(format!("  Impact: {impact}"));
            }
            if let Some(reproduction) = &finding.reproduction {
                lines.push(format!("  Reproduction: {reproduction}"));
            }
            if let Some(limitations) = &finding.limitations {
                lines.push(format!("  Limitations: {limitations}"));
            }
            if !finding.evidence.is_empty() {
                lines.push(format!("  Evidence: {}", finding.evidence.join(", ")));
            }
        }
    }
    if include_evidence {
        lines.push(String::new());
        lines.push("## Evidence".to_string());
        if state.evidence_index.is_empty() {
            lines.push("- No evidence artifacts captured.".to_string());
        } else {
            for evidence in &state.evidence_index {
                lines.push(format!("- {}: {}", evidence.name, evidence.path));
            }
        }
    }
    lines.join("\n")
}

pub(crate) use zap::ZapClient;
pub(crate) use zap::ZapRunRequest;
pub(crate) use zap::ZapScanType;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::test_config;
    use tempfile::tempdir;

    #[test]
    fn security_mode_detects_profile_and_provider() {
        let mut config = test_config();
        assert!(!is_security_config(&config));

        config.active_profile = Some(SECURITY_PROFILE_NAME.to_string());
        assert!(is_security_config(&config));

        config.active_profile = None;
        config.model_provider_id = PENTEST_LOCAL_PROVIDER_ID.to_string();
        assert!(is_security_config(&config));
    }

    #[test]
    fn security_runtime_overrides_preserve_explicit_provider() {
        let mut config = test_config();
        config.active_profile = Some(SECURITY_PROFILE_NAME.to_string());
        let original_provider_id = config.model_provider_id.clone();
        let original_provider = config.model_provider.clone();

        apply_runtime_overrides(&mut config);

        assert_eq!(config.model_provider_id, original_provider_id);
        assert_eq!(config.model_provider, original_provider);
    }

    #[test]
    fn derive_first_target_prefers_url_then_host() {
        assert_eq!(
            derive_first_target_from_text("test https://example.com/login for xss"),
            Some("https://example.com/login".to_string())
        );
        assert_eq!(
            derive_first_target_from_text("inspect example.org next"),
            Some("example.org".to_string())
        );
    }

    #[test]
    fn scope_matches_exact_hosts_and_domains() {
        let scope = SecurityScope {
            mode: "domain".to_string(),
            allowed_hosts: vec!["app.example.com".to_string()],
            allowed_domains: vec!["example.org".to_string()],
            notes: None,
            derived_from: None,
        };
        assert!(scope_allows_host(&scope, "app.example.com"));
        assert!(scope_allows_host(&scope, "api.example.org"));
        assert!(!scope_allows_host(&scope, "evil.example.net"));
    }

    #[tokio::test]
    async fn security_state_persists_findings_and_report() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;
        service
            .validate_scope(&["https://example.com".to_string()], None, true)
            .await
            .expect("scope");
        service
            .record_finding(FindingRecord {
                id: String::new(),
                target: "https://example.com".to_string(),
                vulnerability: "Reflected XSS".to_string(),
                severity: "high".to_string(),
                confidence: "confirmed".to_string(),
                evidence: vec!["resp-1".to_string()],
                reproduction: Some("Replay payload in q parameter".to_string()),
                impact: Some("Arbitrary script execution".to_string()),
                limitations: None,
                status: "confirmed".to_string(),
            })
            .await
            .expect("finding");

        let report = service
            .write_report(Some("Automated security assessment"), true, None)
            .await
            .expect("report");
        let report_contents = std::fs::read_to_string(report).expect("read report");
        assert!(report_contents.contains("Reflected XSS"));
        assert!(report_contents.contains("[finding-0001]"));

        let state_contents = std::fs::read_to_string(&service.state_path).expect("read state");
        assert!(state_contents.contains("Reflected XSS"));
    }

    #[tokio::test]
    async fn security_state_derives_scope_from_current_user_input() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;

        service
            .ensure_default_scope_from_user_input(&[UserInput::Text {
                text: "test http://127.0.0.1:8000 for reflected xss".to_string(),
                text_elements: Vec::new(),
            }])
            .await;

        let snapshot = service.snapshot().await;
        assert_eq!(snapshot.scope.allowed_hosts, vec!["127.0.0.1".to_string()]);
        assert_eq!(
            snapshot.scope.derived_from.as_deref(),
            Some("current_user_input")
        );
    }

    #[tokio::test]
    async fn security_state_persists_recent_commands() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;

        service
            .record_command(ExecutedCommandRecord {
                cmd: "nmap -p- 127.0.0.1".to_string(),
                purpose: "enumerate localhost".to_string(),
                exit_code: Some(0),
                output_preview: Some("8000/tcp open http-alt".to_string()),
                evidence: vec!["scan_output".to_string()],
            })
            .await
            .expect("command");

        let snapshot = service.snapshot().await;
        assert_eq!(snapshot.commands.len(), 1);
        assert_eq!(snapshot.commands[0].cmd, "nmap -p- 127.0.0.1");
    }

    #[tokio::test]
    async fn load_state_assigns_ids_to_legacy_findings_without_ids() {
        let tmp = tempdir().expect("tempdir");
        let thread_id = ThreadId::new();
        let root = tmp.path().join("security").join(thread_id.to_string());
        std::fs::create_dir_all(&root).expect("root");

        let legacy_findings = serde_json::json!([
            {
                "target": "https://example.com",
                "vulnerability": "Reflected XSS",
                "severity": "high",
                "confidence": "confirmed",
                "evidence": ["ev-1"],
                "status": "confirmed"
            }
        ]);
        std::fs::write(
            root.join("findings.json"),
            serde_json::to_vec_pretty(&legacy_findings).expect("serialize findings"),
        )
        .expect("write legacy findings");

        let service = SecuritySessionStateService::new(
            tmp.path(),
            &thread_id,
            true,
            SecurityZapConfig::default(),
        )
        .await;

        let snapshot = service.snapshot().await;
        assert_eq!(snapshot.findings.len(), 1);
        assert_eq!(snapshot.findings[0].id, "finding-0001");
    }

    #[tokio::test]
    async fn write_report_for_single_finding_creates_finding_artifact() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;
        service
            .record_finding(FindingRecord {
                id: String::new(),
                target: "https://example.com".to_string(),
                vulnerability: "Reflected XSS".to_string(),
                severity: "high".to_string(),
                confidence: "confirmed".to_string(),
                evidence: vec!["ev-1".to_string()],
                reproduction: None,
                impact: None,
                limitations: None,
                status: "confirmed".to_string(),
            })
            .await
            .expect("first finding");
        service
            .record_finding(FindingRecord {
                id: String::new(),
                target: "https://example.org".to_string(),
                vulnerability: "SQL Injection".to_string(),
                severity: "critical".to_string(),
                confidence: "confirmed".to_string(),
                evidence: vec!["ev-2".to_string()],
                reproduction: None,
                impact: None,
                limitations: None,
                status: "confirmed".to_string(),
            })
            .await
            .expect("second finding");

        let finding_report = service
            .write_report(None, false, Some("finding-0002"))
            .await
            .expect("finding report");

        let contents = std::fs::read_to_string(&finding_report).expect("read finding report");
        assert!(contents.contains("[finding-0002]"));
        assert!(!contents.contains("[finding-0001]"));
    }

    #[tokio::test]
    async fn save_report_markdown_writes_custom_content_to_session_report() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;

        let report_path = service
            .save_report_markdown("# Custom Report\n\nSaved from the reporting skill.", None)
            .await
            .expect("custom report");

        assert_eq!(report_path, service.report_path);
        let contents = std::fs::read_to_string(&report_path).expect("read custom report");
        assert_eq!(
            contents,
            "# Custom Report\n\nSaved from the reporting skill.\n"
        );
    }

    #[tokio::test]
    async fn save_report_markdown_for_single_finding_uses_finding_artifact_path() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;
        service
            .record_finding(FindingRecord {
                id: String::new(),
                target: "https://example.org".to_string(),
                vulnerability: "SQL Injection".to_string(),
                severity: "critical".to_string(),
                confidence: "confirmed".to_string(),
                evidence: vec!["ev-2".to_string()],
                reproduction: None,
                impact: None,
                limitations: None,
                status: "confirmed".to_string(),
            })
            .await
            .expect("finding");

        let finding_report = service
            .save_report_markdown("## SQL Injection\n\nConfirmed issue.", Some("finding-0001"))
            .await
            .expect("finding report");

        assert!(finding_report.ends_with("report-finding-finding-0001.md"));
        let contents = std::fs::read_to_string(&finding_report).expect("read finding report");
        assert_eq!(contents, "## SQL Injection\n\nConfirmed issue.\n");
    }

    #[test]
    fn disallowed_command_patterns_are_detected() {
        assert_eq!(
            command_contains_disallowed_pattern("curl https://x && rm -rf /tmp/foo"),
            Some("&& rm ")
        );
        assert_eq!(command_contains_disallowed_pattern("curl https://x"), None);
    }

    fn test_security_artifact_paths() -> SecurityArtifactPaths {
        let root_dir = PathBuf::from("/tmp/ux-report-clean-home/security/019d67cb");
        SecurityArtifactPaths {
            evidence_dir: root_dir.join("evidence"),
            state_path: root_dir.join("state.json"),
            findings_path: root_dir.join("findings.json"),
            report_path: root_dir.join("report.md"),
            root_dir,
        }
    }

    #[test]
    fn command_validation_blocks_out_of_scope_tokens() {
        let scope = SecurityScope {
            mode: "host_only".to_string(),
            allowed_hosts: vec!["example.com".to_string()],
            allowed_domains: Vec::new(),
            notes: None,
            derived_from: None,
        };
        let err = command_is_allowed(
            &[vec!["curl".to_string(), "https://evil.test".to_string()]],
            &[],
            &[],
            &[],
            &scope,
            &test_security_artifact_paths(),
        )
        .expect_err("should reject");
        assert!(matches!(err, FunctionCallError::RespondToModel(_)));
    }

    #[test]
    fn local_paths_do_not_parse_as_hosts() {
        assert_eq!(
            maybe_extract_host_from_token("/tmp/report-structure.md"),
            None
        );
        assert_eq!(maybe_extract_host_from_token("./findings.json"), None);
        assert_eq!(
            maybe_extract_host_from_token("file:///tmp/security/report.md"),
            None
        );
    }

    #[test]
    fn command_validation_allows_local_artifact_reads() {
        let scope = SecurityScope {
            mode: "host_only".to_string(),
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allowed_domains: Vec::new(),
            notes: None,
            derived_from: None,
        };

        command_is_allowed(
            &[vec![
                "sed".to_string(),
                "-n".to_string(),
                "1,20p".to_string(),
                "/tmp/ux-report-clean-home/security/019d67cb/report-structure.md".to_string(),
            ]],
            &[],
            &[
                "/tmp/ux-report-clean-home/security/019d67cb/findings.json".to_string(),
                "/tmp/ux-report-clean-home/security/019d67cb/report-structure.md".to_string(),
                "/tmp/ux-report-clean-home/security/019d67cb/evidence".to_string(),
                "/tmp/ux-report-clean-home/security/019d67cb/report.md".to_string(),
            ],
            &[],
            &scope,
            &test_security_artifact_paths(),
        )
        .expect("local file reads should stay allowed");
    }

    #[test]
    fn command_validation_rejects_local_paths_outside_allowlist() {
        let scope = SecurityScope {
            mode: "host_only".to_string(),
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allowed_domains: Vec::new(),
            notes: None,
            derived_from: None,
        };

        let err = command_is_allowed(
            &[vec![
                "sed".to_string(),
                "-n".to_string(),
                "1,20p".to_string(),
                "/root/secret.txt".to_string(),
            ]],
            &[],
            &["/tmp/ux-report-clean-home/security/019d67cb".to_string()],
            &[],
            &scope,
            &test_security_artifact_paths(),
        )
        .expect_err("out-of-allowlist local reads should be rejected");

        assert!(
            matches!(err, FunctionCallError::RespondToModel(message) if message.contains("allowed security artifact paths"))
        );
    }

    #[test]
    fn command_validation_rejects_manual_artifact_fabrication() {
        let scope = SecurityScope {
            mode: "host_only".to_string(),
            allowed_hosts: vec!["127.0.0.1".to_string()],
            allowed_domains: Vec::new(),
            notes: None,
            derived_from: None,
        };

        let err = command_is_allowed(
            &[vec![
                "python3".to_string(),
                "/tmp/write-report.py".to_string(),
                "/tmp/ux-report-clean-home/security/019d67cb/report.md".to_string(),
            ]],
            &[],
            &["/tmp/ux-report-clean-home/security/019d67cb/report.md".to_string()],
            &[],
            &scope,
            &test_security_artifact_paths(),
        )
        .expect_err("manual artifact fabrication should be rejected");

        assert!(
            matches!(err, FunctionCallError::RespondToModel(message) if message.contains("written only through `capture_evidence`, `record_finding`, and `report_write`"))
        );
    }

    #[test]
    fn generic_exec_guard_rejects_broad_artifact_searches() {
        let err = generic_exec_command_security_violation(
            "rg -n --hidden --glob 'findings.json' --glob 'report.md' --glob 'state.json' 'findings|report|state' /root",
            &test_security_artifact_paths(),
        )
        .expect("broad artifact search should be rejected");

        assert!(err.contains("do not run broad local searches"));
    }

    #[test]
    fn generic_exec_guard_rejects_manual_security_artifact_writes() {
        let err = generic_exec_command_security_violation(
            "printf '{}' > /tmp/ux-report-clean-home/security/019d67cb/findings.json",
            &test_security_artifact_paths(),
        )
        .expect("manual artifact write should be rejected");

        assert!(err.contains(
            "written only through `capture_evidence`, `record_finding`, and `report_write`"
        ));
    }

    #[tokio::test]
    async fn exact_url_scope_rejects_different_path_on_same_host() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;

        service
            .validate_scope(&["http://127.0.0.1:8876/login".to_string()], None, false)
            .await
            .expect("scope");

        let err = service
            .ensure_url_in_scope("http://127.0.0.1:8876/auth/login")
            .await
            .expect_err("route drift should be rejected");

        assert!(
            matches!(err, FunctionCallError::RespondToModel(message) if message.contains("exact security scope"))
        );
    }

    #[tokio::test]
    async fn exact_url_scope_allows_query_on_same_url() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;

        service
            .validate_scope(&["http://127.0.0.1:8876/login".to_string()], None, false)
            .await
            .expect("scope");

        service
            .ensure_url_in_scope("http://127.0.0.1:8876/login?user=analyst")
            .await
            .expect("same path with query should remain in scope");
    }

    #[test]
    fn command_validation_rejects_exact_url_drift() {
        let scope = SecurityScope {
            mode: "host_only".to_string(),
            allowed_hosts: vec!["127.0.0.1:8876".to_string()],
            allowed_domains: Vec::new(),
            notes: None,
            derived_from: None,
        };

        let err = command_is_allowed(
            &[vec![
                "curl".to_string(),
                "http://127.0.0.1:8876/auth/login".to_string(),
            ]],
            &[],
            &[],
            &["http://127.0.0.1:8876/login".to_string()],
            &scope,
            &test_security_artifact_paths(),
        )
        .expect_err("exact URL drift should be rejected");

        assert!(
            matches!(err, FunctionCallError::RespondToModel(message) if message.contains("exact security scope"))
        );
    }

    #[tokio::test]
    async fn validate_scope_rejects_local_file_targets() {
        let tmp = tempdir().expect("tempdir");
        let service = SecuritySessionStateService::new(
            tmp.path(),
            &ThreadId::default(),
            true,
            SecurityZapConfig::default(),
        )
        .await;

        let err = service
            .validate_scope(
                &["/tmp/ux-report-clean-home/security/thread/findings.json".to_string()],
                None,
                false,
            )
            .await
            .expect_err("local file paths should be rejected");

        assert!(
            matches!(err, FunctionCallError::RespondToModel(message) if message.contains("scope_validate does not accept local file paths"))
        );
    }
}
