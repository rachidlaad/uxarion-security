use crate::bash::try_parse_shell;
use crate::bash::try_parse_word_only_commands_sequence;
use crate::function_tool::FunctionCallError;
use crate::security::ExecutedCommandRecord;
use crate::security::FindingRecord;
use crate::security::command_contains_disallowed_pattern;
use crate::security::command_is_allowed;
use crate::tools::context::ExecCommandToolOutput;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::UnifiedExecHandler;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct SecurityExecHandler;
pub struct ScopeValidateHandler;
pub struct HttpInspectHandler;
pub struct CaptureEvidenceHandler;
pub struct RecordFindingHandler;
pub struct ReportWriteHandler;

#[derive(Debug, Deserialize)]
struct SecurityExecArgs {
    cmd: String,
    #[serde(default)]
    workdir: Option<String>,
    #[serde(default)]
    shell: Option<String>,
    #[serde(default)]
    login: Option<bool>,
    #[serde(default = "default_exec_tty")]
    tty: bool,
    #[serde(default = "default_exec_yield_time_ms")]
    yield_time_ms: u64,
    #[serde(default)]
    max_output_tokens: Option<usize>,
    purpose: String,
    #[serde(default)]
    scope_targets: Vec<String>,
    #[serde(default)]
    risk_level: Option<String>,
    #[serde(default)]
    expected_artifacts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ScopeValidateArgs {
    targets: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Deserialize)]
struct HttpInspectArgs {
    url: String,
    #[serde(default = "default_http_method")]
    method: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    capture_body: bool,
    #[serde(default = "default_http_body_bytes")]
    max_body_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct CaptureEvidenceArgs {
    name: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    source_path: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RecordFindingArgs {
    target: String,
    vulnerability: String,
    severity: String,
    confidence: String,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    reproduction: Option<String>,
    #[serde(default)]
    impact: Option<String>,
    #[serde(default)]
    limitations: Option<String>,
    #[serde(default = "default_finding_status")]
    status: String,
}

#[derive(Debug, Deserialize)]
struct ReportWriteArgs {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    include_evidence: bool,
    #[serde(default)]
    finding_id: Option<String>,
}

fn default_exec_yield_time_ms() -> u64 {
    10_000
}

fn default_exec_tty() -> bool {
    false
}

fn default_http_method() -> String {
    "GET".to_string()
}

fn default_http_body_bytes() -> usize {
    8_192
}

fn default_finding_status() -> String {
    "confirmed".to_string()
}

fn parse_security_exec_words(cmd: &str) -> Option<Vec<Vec<String>>> {
    let parsed = try_parse_shell(cmd)
        .and_then(|tree| try_parse_word_only_commands_sequence(&tree, cmd))
        .filter(|commands| !commands.is_empty());
    if parsed.is_some() {
        return parsed;
    }

    if cmd
        .chars()
        .any(|ch| matches!(ch, '|' | '&' | ';' | '>' | '<' | '\n'))
    {
        return None;
    }

    shlex::split(cmd).map(|words| vec![words]).filter(|words| {
        words
            .first()
            .and_then(|command| command.first())
            .is_some_and(|binary| !binary.is_empty())
    })
}

fn payload_arguments(payload: ToolPayload) -> Result<String, FunctionCallError> {
    match payload {
        ToolPayload::Function { arguments } => Ok(arguments),
        _ => Err(FunctionCallError::RespondToModel(
            "security handler received unsupported payload".to_string(),
        )),
    }
}

#[async_trait]
impl ToolHandler for SecurityExecHandler {
    type Output = ExecCommandToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            tracker,
            call_id,
            payload,
            ..
        } = invocation;

        let arguments = payload_arguments(payload)?;
        let args: SecurityExecArgs = parse_arguments(&arguments)?;
        if args.cmd.trim().is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "`cmd` must not be empty".to_string(),
            ));
        }
        if args.purpose.trim().is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "`purpose` must describe why the command is being run".to_string(),
            ));
        }
        if let Some(risk_level) = args.risk_level.as_deref()
            && matches!(risk_level, "destructive" | "critical")
        {
            return Err(FunctionCallError::RespondToModel(
                "destructive security_exec commands are blocked in v1".to_string(),
            ));
        }
        if let Some(pattern) = command_contains_disallowed_pattern(&args.cmd) {
            return Err(FunctionCallError::RespondToModel(format!(
                "security_exec blocked a destructive command pattern: `{pattern}`"
            )));
        }

        let parsed_words = parse_security_exec_words(&args.cmd).ok_or_else(|| {
            FunctionCallError::RespondToModel(
                "security_exec could not safely inspect this shell command; pass a direct command or a simple pipeline/sequence without nested shells or redirections".to_string(),
            )
        })?;
        let snapshot = session.services.security_state.snapshot().await;
        command_is_allowed(&parsed_words, &args.scope_targets, &snapshot.scope)?;
        session
            .services
            .security_state
            .ensure_targets_in_scope(&args.scope_targets)
            .await?;

        let exec_arguments = json!({
            "cmd": args.cmd,
            "workdir": args.workdir,
            "shell": args.shell,
            "login": args.login,
            "tty": args.tty,
            "yield_time_ms": args.yield_time_ms,
            "max_output_tokens": args.max_output_tokens,
        })
        .to_string();

        let unified_exec_handler = UnifiedExecHandler;
        let output = unified_exec_handler
            .handle(ToolInvocation {
                session: session.clone(),
                turn: turn.clone(),
                tracker,
                call_id,
                tool_name: "exec_command".to_string(),
                payload: ToolPayload::Function {
                    arguments: exec_arguments,
                },
            })
            .await?;

        let mut evidence_ids = Vec::new();
        let output_preview = output.truncated_output();
        if !output_preview.trim().is_empty() {
            let evidence = session
                .services
                .security_state
                .capture_text_evidence(
                    "security_exec_output",
                    &output_preview,
                    Some("text/plain".to_string()),
                    Some(format!("Command output for `{}`", args.cmd)),
                    Some("security_exec".to_string()),
                )
                .await?;
            evidence_ids.push(evidence.id);
        }

        if !args.expected_artifacts.is_empty() {
            let workdir = args
                .workdir
                .as_ref()
                .map(PathBuf::from)
                .map_or_else(|| turn.cwd.clone(), |path| turn.cwd.join(path));
            let captured = session
                .services
                .security_state
                .capture_expected_artifacts(&workdir, &args.expected_artifacts)
                .await?;
            evidence_ids.extend(captured.into_iter().map(|record| record.id));
        }

        session
            .services
            .security_state
            .record_command(ExecutedCommandRecord {
                cmd: args.cmd.clone(),
                purpose: args.purpose,
                exit_code: output.exit_code,
                output_preview: (!output_preview.trim().is_empty()).then_some(output_preview),
                evidence: evidence_ids,
            })
            .await?;

        Ok(output)
    }
}

#[async_trait]
impl ToolHandler for ScopeValidateHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session, payload, ..
        } = invocation;
        let arguments = payload_arguments(payload)?;
        let args: ScopeValidateArgs = parse_arguments(&arguments)?;
        let state = session
            .services
            .security_state
            .validate_scope(&args.targets, args.notes, args.replace)
            .await?;
        let output = json!({
            "scope": state.scope,
            "targets": state.targets,
        });
        Ok(FunctionToolOutput::from_text(
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| output.to_string()),
            Some(true),
        ))
    }
}

#[async_trait]
impl ToolHandler for HttpInspectHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session, payload, ..
        } = invocation;
        let arguments = payload_arguments(payload)?;
        let args: HttpInspectArgs = parse_arguments(&arguments)?;
        session
            .services
            .security_state
            .http_inspect(
                &args.url,
                &args.method,
                &args.headers,
                args.body.as_deref(),
                args.capture_body,
                args.max_body_bytes,
            )
            .await
    }
}

#[async_trait]
impl ToolHandler for CaptureEvidenceHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session,
            turn,
            payload,
            ..
        } = invocation;
        let arguments = payload_arguments(payload)?;
        let args: CaptureEvidenceArgs = parse_arguments(&arguments)?;
        let CaptureEvidenceArgs {
            name,
            content,
            source_path,
            notes,
            source,
            media_type,
        } = args;
        let record = if let Some(content) = content.as_deref() {
            session
                .services
                .security_state
                .capture_text_evidence(
                    &name,
                    content,
                    media_type.clone(),
                    notes.clone(),
                    source.clone(),
                )
                .await?
        } else if let Some(source_path) = source_path.as_deref() {
            let path = if PathBuf::from(source_path).is_absolute() {
                PathBuf::from(source_path)
            } else {
                turn.cwd.join(source_path)
            };
            session
                .services
                .security_state
                .capture_file_evidence(&name, &path, media_type, notes, source)
                .await?
                .ok_or_else(|| {
                    FunctionCallError::RespondToModel(format!(
                        "source_path `{}` does not point to a regular file",
                        path.display()
                    ))
                })?
        } else {
            return Err(FunctionCallError::RespondToModel(
                "capture_evidence requires either `content` or `source_path`".to_string(),
            ));
        };

        Ok(FunctionToolOutput::from_text(
            serde_json::to_string_pretty(&record).unwrap_or_else(|_| "{}".to_string()),
            Some(true),
        ))
    }
}

#[async_trait]
impl ToolHandler for RecordFindingHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session, payload, ..
        } = invocation;
        let arguments = payload_arguments(payload)?;
        let args: RecordFindingArgs = parse_arguments(&arguments)?;
        let state = session
            .services
            .security_state
            .record_finding(FindingRecord {
                id: String::new(),
                target: args.target,
                vulnerability: args.vulnerability,
                severity: args.severity,
                confidence: args.confidence,
                evidence: args.evidence,
                reproduction: args.reproduction,
                impact: args.impact,
                limitations: args.limitations,
                status: args.status,
            })
            .await?;
        let output = json!({
            "finding_count": state.findings.len(),
            "latest_finding": state.findings.last(),
        });
        Ok(FunctionToolOutput::from_text(
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| output.to_string()),
            Some(true),
        ))
    }
}

#[async_trait]
impl ToolHandler for ReportWriteHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session, payload, ..
        } = invocation;
        let arguments = payload_arguments(payload)?;
        let args: ReportWriteArgs = parse_arguments(&arguments)?;
        let report_path = if let Some(content) = args.content.as_deref() {
            if args.summary.is_some() || args.include_evidence {
                return Err(FunctionCallError::RespondToModel(
                    "`content` cannot be combined with `summary` or `include_evidence`".to_string(),
                ));
            }
            session
                .services
                .security_state
                .save_report_markdown(content, args.finding_id.as_deref())
                .await?
        } else {
            session
                .services
                .security_state
                .write_report(
                    args.summary.as_deref(),
                    args.include_evidence,
                    args.finding_id.as_deref(),
                )
                .await?
        };
        let output = json!({
            "report_path": report_path,
        });
        Ok(FunctionToolOutput::from_text(
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| output.to_string()),
            Some(true),
        ))
    }
}
