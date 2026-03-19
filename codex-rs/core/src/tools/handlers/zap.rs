use crate::function_tool::FunctionCallError;
use crate::security::ZapClient;
use crate::security::ZapRunRequest;
use crate::security::ZapScanType;
use crate::tools::context::FunctionToolOutput;
use crate::tools::context::ToolInvocation;
use crate::tools::context::ToolPayload;
use crate::tools::handlers::parse_arguments;
use crate::tools::registry::ToolHandler;
use crate::tools::registry::ToolKind;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

pub struct ZapRunHandler;

#[derive(Debug, Deserialize)]
struct ZapRunArgs {
    target: String,
    #[serde(default = "default_scan_type")]
    scan_type: String,
    #[serde(default = "default_max_minutes")]
    max_minutes: u64,
    #[serde(default = "default_max_alerts")]
    max_alerts: usize,
}

fn default_scan_type() -> String {
    "spider".to_string()
}

fn default_max_minutes() -> u64 {
    10
}

fn default_max_alerts() -> usize {
    25
}

fn payload_arguments(payload: ToolPayload) -> Result<String, FunctionCallError> {
    match payload {
        ToolPayload::Function { arguments } => Ok(arguments),
        _ => Err(FunctionCallError::RespondToModel(
            "zap handler received unsupported payload".to_string(),
        )),
    }
}

#[async_trait]
impl ToolHandler for ZapRunHandler {
    type Output = FunctionToolOutput;

    fn kind(&self) -> ToolKind {
        ToolKind::Function
    }

    async fn handle(&self, invocation: ToolInvocation) -> Result<Self::Output, FunctionCallError> {
        let ToolInvocation {
            session, payload, ..
        } = invocation;
        let arguments = payload_arguments(payload)?;
        let args: ZapRunArgs = parse_arguments(&arguments)?;
        if args.target.trim().is_empty() {
            return Err(FunctionCallError::RespondToModel(
                "`target` must not be empty".to_string(),
            ));
        }

        session
            .services
            .security_state
            .ensure_url_in_scope(&args.target)
            .await?;

        let client = ZapClient::from_env();
        let scan_type = ZapScanType::parse(&args.scan_type)?;
        let result = client
            .run_scan(&ZapRunRequest {
                target: args.target,
                scan_type,
                max_minutes: args.max_minutes,
                max_alerts: args.max_alerts,
            })
            .await?;

        if !result.discovered_urls.is_empty() {
            session
                .services
                .security_state
                .record_discovered_urls(&result.discovered_urls)
                .await?;
        }

        let scan_notes = format!(
            "ZAP {:?} scan against {} via {}",
            result.scan_type, result.target, result.zap_base_url
        );
        let summary_json =
            serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string());
        let summary_record = session
            .services
            .security_state
            .capture_text_evidence(
                "zap_run_summary",
                &summary_json,
                Some("application/json".to_string()),
                Some(scan_notes),
                Some(result.zap_base_url.clone()),
            )
            .await?;

        let alerts_json =
            serde_json::to_string_pretty(&result.alerts).unwrap_or_else(|_| "[]".to_string());
        let alerts_record = session
            .services
            .security_state
            .capture_text_evidence(
                "zap_alerts",
                &alerts_json,
                Some("application/json".to_string()),
                Some(format!("Raw ZAP alerts for {}", result.target)),
                Some(result.zap_base_url.clone()),
            )
            .await?;

        let output = json!({
            "target": result.target,
            "zap_base_url": result.zap_base_url,
            "version": result.version,
            "scan_type": result.scan_type,
            "spider": result.spider,
            "active_scan": result.active_scan,
            "discovered_urls": result.discovered_urls,
            "alert_count": result.alert_count,
            "alerts_truncated": result.alerts_truncated,
            "alerts": result.alerts,
            "evidence": [summary_record.id, alerts_record.id],
        });

        Ok(FunctionToolOutput::from_text(
            serde_json::to_string_pretty(&output).unwrap_or_else(|_| output.to_string()),
            Some(true),
        ))
    }
}
