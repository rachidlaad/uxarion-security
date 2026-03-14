use crate::config::Config;
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

mod zap;

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

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SecurityToolInventory {
    pub available: Vec<String>,
    pub missing: Vec<String>,
    pub zap_api_base_url: String,
    pub zap_api_key_configured: bool,
}

impl SecurityToolInventory {
    fn discover() -> Self {
        let zap_api_key = zap::resolve_zap_api_key();
        let mut available = Vec::new();
        let mut missing = Vec::new();
        for binary in SECURITY_BINARY_ALLOWLIST {
            if which::which(binary).is_ok() {
                available.push((*binary).to_string());
            } else {
                missing.push((*binary).to_string());
            }
        }
        available.sort();
        missing.sort();
        Self {
            available,
            missing,
            zap_api_base_url: zap::resolve_zap_base_url(),
            zap_api_key_configured: zap_api_key.is_some(),
        }
    }
}

pub(crate) fn is_security_config(config: &Config) -> bool {
    config.active_profile.as_deref() == Some(SECURITY_PROFILE_NAME)
        || config.model_provider_id == PENTEST_LOCAL_PROVIDER_ID
}

pub(crate) fn apply_runtime_overrides(config: &mut Config) {
    if !is_security_config(config) {
        return;
    }

    if config.model_provider_id != PENTEST_LOCAL_PROVIDER_ID
        && let Some(provider) = crate::model_provider_info::built_in_model_providers()
            .get(PENTEST_LOCAL_PROVIDER_ID)
            .cloned()
    {
        config.model_provider_id = PENTEST_LOCAL_PROVIDER_ID.to_string();
        config.model_provider = provider;
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
    inventory: SecurityToolInventory,
    state: Mutex<SecuritySessionState>,
}

impl SecuritySessionStateService {
    pub(crate) async fn new(codex_home: &Path, thread_id: &ThreadId, enabled: bool) -> Self {
        let root_dir = codex_home.join("security").join(thread_id.to_string());
        let evidence_dir = root_dir.join("evidence");
        let state_path = root_dir.join("state.json");
        let findings_path = root_dir.join("findings.json");
        let report_path = root_dir.join("report.md");
        let inventory = SecurityToolInventory::discover();

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

    pub(crate) fn render_tool_inventory_fragment(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }

        serde_json::to_string_pretty(&self.inventory).ok()
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
        if scope_allows_host(&state.scope, &host) {
            Ok(())
        } else {
            Err(FunctionCallError::RespondToModel(format!(
                "target `{host}` is outside the current security scope; update scope explicitly before testing it"
            )))
        }
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
        finding: FindingRecord,
    ) -> Result<SecuritySessionState, FunctionCallError> {
        if !self.enabled {
            return Err(FunctionCallError::RespondToModel(
                "security state is disabled for this session".to_string(),
            ));
        }

        let mut state = self.state.lock().await;
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
        let report = render_report_markdown(&snapshot, summary, include_evidence);
        fs::write(&self.report_path, report).await.map_err(|err| {
            FunctionCallError::RespondToModel(format!("failed to write security report: {err}"))
        })?;
        Ok(self.report_path.clone())
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
    Some(state)
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
    parsed
        .host_str()
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            FunctionCallError::RespondToModel(format!(
                "URL `{input}` does not include a valid host"
            ))
        })
}

fn parse_host_or_literal(input: &str) -> Result<String, FunctionCallError> {
    if input.contains("://") {
        return parse_host(input);
    }
    Ok(input.trim().trim_matches('/').to_ascii_lowercase())
}

pub(crate) fn scope_allows_host(scope: &SecurityScope, host: &str) -> bool {
    let normalized = host.to_ascii_lowercase();
    if scope.allowed_hosts.iter().any(|entry| entry == &normalized) {
        return true;
    }

    scope
        .allowed_domains
        .iter()
        .any(|domain| normalized == *domain || normalized.ends_with(&format!(".{domain}")))
}

pub(crate) fn command_is_allowed(
    command_words: &[Vec<String>],
    scope_targets: &[String],
    current_scope: &SecurityScope,
) -> Result<(), FunctionCallError> {
    if command_words.is_empty() {
        return Err(FunctionCallError::RespondToModel(
            "security_exec requires a concrete command".to_string(),
        ));
    }

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
        for token in command {
            if let Some(host) = maybe_extract_host_from_token(token)
                && !scope_allows_host(current_scope, &host)
            {
                return Err(FunctionCallError::RespondToModel(format!(
                    "command target `{host}` is outside the current security scope"
                )));
            }
        }
    }

    for target in scope_targets {
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
    if token.starts_with('-') {
        return None;
    }
    if let Ok(parsed) = Url::parse(token) {
        return parsed.host_str().map(str::to_ascii_lowercase);
    }
    if HOST_REGEX.is_match(token) || IPV4_REGEX.is_match(token) {
        return Some(token.trim_matches('/').to_ascii_lowercase());
    }
    None
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
                "- {} on {} [{} / {} / {}]",
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
        let service =
            SecuritySessionStateService::new(tmp.path(), &ThreadId::default(), true).await;
        service
            .validate_scope(&["https://example.com".to_string()], None, true)
            .await
            .expect("scope");
        service
            .record_finding(FindingRecord {
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
            .write_report(Some("Automated security assessment"), true)
            .await
            .expect("report");
        let report_contents = std::fs::read_to_string(report).expect("read report");
        assert!(report_contents.contains("Reflected XSS"));

        let state_contents = std::fs::read_to_string(&service.state_path).expect("read state");
        assert!(state_contents.contains("Reflected XSS"));
    }

    #[tokio::test]
    async fn security_state_derives_scope_from_current_user_input() {
        let tmp = tempdir().expect("tempdir");
        let service =
            SecuritySessionStateService::new(tmp.path(), &ThreadId::default(), true).await;

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
        let service =
            SecuritySessionStateService::new(tmp.path(), &ThreadId::default(), true).await;

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

    #[test]
    fn disallowed_command_patterns_are_detected() {
        assert_eq!(
            command_contains_disallowed_pattern("curl https://x && rm -rf /tmp/foo"),
            Some("&& rm ")
        );
        assert_eq!(command_contains_disallowed_pattern("curl https://x"), None);
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
            &scope,
        )
        .expect_err("should reject");
        assert!(matches!(err, FunctionCallError::RespondToModel(_)));
    }
}
