use crate::default_client::build_reqwest_client;
use crate::function_tool::FunctionCallError;
use crate::security::parse_host;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;
use std::time::Instant;
use tokio::time::sleep;
use url::Url;

pub(crate) const UXARION_ZAP_BASE_URL_ENV_VAR: &str = "UXARION_ZAP_BASE_URL";
pub(crate) const UXARION_ZAP_API_KEY_ENV_VAR: &str = "UXARION_ZAP_API_KEY";
pub(crate) const DEFAULT_ZAP_BASE_URL: &str = "http://172.17.160.1:8080";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const ALERTS_PAGE_SIZE: usize = 250;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ZapClientConfig {
    pub base_url: String,
    pub api_key: Option<String>,
}

impl Default for ZapClientConfig {
    fn default() -> Self {
        Self {
            base_url: resolve_zap_base_url(),
            api_key: resolve_zap_api_key(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ZapScanType {
    Passive,
    Spider,
    Active,
}

impl ZapScanType {
    pub(crate) fn parse(value: &str) -> Result<Self, FunctionCallError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "passive" => Ok(Self::Passive),
            "spider" | "baseline" => Ok(Self::Spider),
            "active" | "full" => Ok(Self::Active),
            other => Err(FunctionCallError::RespondToModel(format!(
                "unsupported zap scan type `{other}`; use passive, spider, or active"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ZapRunRequest {
    pub target: String,
    pub scan_type: ZapScanType,
    pub max_minutes: u64,
    pub max_alerts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ZapAlertSummary {
    pub name: String,
    pub risk: String,
    pub confidence: String,
    pub url: String,
    pub param: Option<String>,
    pub attack: Option<String>,
    pub description: Option<String>,
    pub plugin_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ZapScanProgress {
    pub scan_id: String,
    pub status: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ZapRunResult {
    pub target: String,
    pub zap_base_url: String,
    pub version: String,
    pub scan_type: ZapScanType,
    pub spider: Option<ZapScanProgress>,
    pub active_scan: Option<ZapScanProgress>,
    pub discovered_urls: Vec<String>,
    pub alert_count: usize,
    pub alerts: Vec<ZapAlertSummary>,
    pub alerts_truncated: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ZapClient {
    config: ZapClientConfig,
    client: reqwest::Client,
}

impl ZapClient {
    pub(crate) fn from_env() -> Self {
        Self::new(ZapClientConfig::default())
    }

    pub(crate) fn new(config: ZapClientConfig) -> Self {
        Self {
            config: normalize_config(config),
            client: build_reqwest_client(),
        }
    }

    pub(crate) async fn run_scan(
        &self,
        request: &ZapRunRequest,
    ) -> Result<ZapRunResult, FunctionCallError> {
        let target_host = parse_host(&request.target)?;
        let version = self.version().await?;
        self.access_url(&request.target).await?;

        let deadline = Instant::now()
            .checked_add(Duration::from_secs(request.max_minutes.saturating_mul(60)))
            .unwrap_or_else(Instant::now);

        let spider = if matches!(request.scan_type, ZapScanType::Spider | ZapScanType::Active) {
            let scan_id = self.start_spider(&request.target).await?;
            Some(
                self.wait_for_percent_status("spider", &scan_id, deadline)
                    .await?,
            )
        } else {
            None
        };

        let active_scan = if matches!(request.scan_type, ZapScanType::Active) {
            let scan_id = self.start_active_scan(&request.target).await?;
            Some(
                self.wait_for_percent_status("ascan", &scan_id, deadline)
                    .await?,
            )
        } else {
            None
        };

        let alerts = self.alerts(&request.target, request.max_alerts).await?;
        let discovered_urls = self.urls_for_host(&target_host).await?;
        let alerts_truncated = alerts.len() == request.max_alerts;

        Ok(ZapRunResult {
            target: request.target.clone(),
            zap_base_url: self.config.base_url.clone(),
            version,
            scan_type: request.scan_type,
            spider,
            active_scan,
            discovered_urls,
            alert_count: alerts.len(),
            alerts,
            alerts_truncated,
        })
    }

    async fn version(&self) -> Result<String, FunctionCallError> {
        let json = self
            .json_api("core", "view", "version", Vec::<(&str, String)>::new())
            .await?;
        json_string_field(&json, "version", "ZAP version")
    }

    async fn access_url(&self, url: &str) -> Result<(), FunctionCallError> {
        self.json_api(
            "core",
            "action",
            "accessUrl",
            vec![("url", url.to_string())],
        )
        .await?;
        Ok(())
    }

    async fn start_spider(&self, url: &str) -> Result<String, FunctionCallError> {
        let json = self
            .json_api("spider", "action", "scan", vec![("url", url.to_string())])
            .await?;
        json_string_field(&json, "scan", "ZAP spider scan id")
    }

    async fn start_active_scan(&self, url: &str) -> Result<String, FunctionCallError> {
        let json = self
            .json_api("ascan", "action", "scan", vec![("url", url.to_string())])
            .await?;
        json_string_field(&json, "scan", "ZAP active scan id")
    }

    async fn wait_for_percent_status(
        &self,
        component: &str,
        scan_id: &str,
        deadline: Instant,
    ) -> Result<ZapScanProgress, FunctionCallError> {
        loop {
            let json = self
                .json_api(
                    component,
                    "view",
                    "status",
                    vec![("scanId", scan_id.to_string())],
                )
                .await?;
            let status = json_string_field(&json, "status", "ZAP scan status")?
                .parse::<u8>()
                .map_err(|err| {
                    FunctionCallError::RespondToModel(format!(
                        "failed to parse ZAP scan status for `{component}`: {err}"
                    ))
                })?;
            if status >= 100 {
                return Ok(ZapScanProgress {
                    scan_id: scan_id.to_string(),
                    status,
                });
            }
            if Instant::now() >= deadline {
                return Err(FunctionCallError::RespondToModel(format!(
                    "ZAP `{component}` scan timed out before completion"
                )));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn alerts(
        &self,
        target: &str,
        max_alerts: usize,
    ) -> Result<Vec<ZapAlertSummary>, FunctionCallError> {
        let mut alerts = Vec::new();
        let mut start = 0usize;

        while alerts.len() < max_alerts {
            let remaining = max_alerts.saturating_sub(alerts.len());
            let count = remaining.min(ALERTS_PAGE_SIZE);
            let json = self
                .json_api(
                    "alert",
                    "view",
                    "alerts",
                    vec![
                        ("baseurl", target.to_string()),
                        ("start", start.to_string()),
                        ("count", count.to_string()),
                    ],
                )
                .await?;
            let Some(raw_alerts) = json.get("alerts").and_then(Value::as_array) else {
                return Err(FunctionCallError::RespondToModel(
                    "ZAP alerts response did not include an `alerts` array".to_string(),
                ));
            };
            if raw_alerts.is_empty() {
                break;
            }

            for raw_alert in raw_alerts {
                alerts.push(parse_alert_summary(raw_alert)?);
                if alerts.len() >= max_alerts {
                    break;
                }
            }

            if raw_alerts.len() < count {
                break;
            }
            start += raw_alerts.len();
        }

        Ok(alerts)
    }

    async fn urls_for_host(&self, host: &str) -> Result<Vec<String>, FunctionCallError> {
        let json = self
            .json_api("core", "view", "urls", Vec::<(&str, String)>::new())
            .await?;
        let Some(urls) = json.get("urls").and_then(Value::as_array) else {
            return Err(FunctionCallError::RespondToModel(
                "ZAP URLs response did not include a `urls` array".to_string(),
            ));
        };

        let mut discovered = BTreeSet::new();
        for value in urls {
            let Some(url) = value.as_str() else {
                continue;
            };
            if Url::parse(url)
                .ok()
                .and_then(|parsed| parsed.host_str().map(str::to_ascii_lowercase))
                .is_some_and(|url_host| url_host == host)
            {
                discovered.insert(url.to_string());
            }
        }

        Ok(discovered.into_iter().collect())
    }

    async fn json_api(
        &self,
        component: &str,
        category: &str,
        operation: &str,
        params: Vec<(&str, String)>,
    ) -> Result<Value, FunctionCallError> {
        let mut query = params;
        if let Some(api_key) = &self.config.api_key {
            query.push(("apikey", api_key.clone()));
        }

        let url = format!(
            "{}/JSON/{component}/{category}/{operation}/",
            self.config.base_url
        );
        let response = self
            .client
            .get(url)
            .query(&query)
            .send()
            .await
            .map_err(|err| {
                FunctionCallError::RespondToModel(format!(
                    "failed to reach ZAP API at `{}`: {err}",
                    self.config.base_url
                ))
            })?;
        let status = response.status();
        let body = response.text().await.map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to read ZAP API response body: {err}"
            ))
        })?;
        if !status.is_success() {
            return Err(FunctionCallError::RespondToModel(format!(
                "ZAP API returned HTTP {status} for `{component}/{category}/{operation}`: {body}"
            )));
        }

        serde_json::from_str(&body).map_err(|err| {
            FunctionCallError::RespondToModel(format!(
                "failed to parse ZAP API response for `{component}/{category}/{operation}`: {err}"
            ))
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawZapAlert {
    #[serde(rename = "alert")]
    name: String,
    risk: String,
    confidence: String,
    url: String,
    param: Option<String>,
    attack: Option<String>,
    description: Option<String>,
    #[serde(rename = "pluginId")]
    plugin_id: Option<String>,
}

pub(crate) fn resolve_zap_base_url() -> String {
    std::env::var(UXARION_ZAP_BASE_URL_ENV_VAR)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_ZAP_BASE_URL.to_string())
}

pub(crate) fn resolve_zap_api_key() -> Option<String> {
    std::env::var(UXARION_ZAP_API_KEY_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn normalize_config(config: ZapClientConfig) -> ZapClientConfig {
    let base_url = config.base_url.trim().trim_end_matches('/').to_string();
    ZapClientConfig {
        base_url: if base_url.is_empty() {
            DEFAULT_ZAP_BASE_URL.to_string()
        } else {
            base_url
        },
        api_key: config.api_key.filter(|value| !value.trim().is_empty()),
    }
}

fn json_string_field(
    json: &Value,
    field_name: &str,
    label: &str,
) -> Result<String, FunctionCallError> {
    json.get(field_name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            FunctionCallError::RespondToModel(format!(
                "{label} was missing from the ZAP API response"
            ))
        })
}

fn parse_alert_summary(value: &Value) -> Result<ZapAlertSummary, FunctionCallError> {
    let raw = serde_json::from_value::<RawZapAlert>(value.clone()).map_err(|err| {
        FunctionCallError::RespondToModel(format!("failed to parse ZAP alert summary: {err}"))
    })?;
    Ok(ZapAlertSummary {
        name: raw.name,
        risk: raw.risk,
        confidence: raw.confidence,
        url: raw.url,
        param: raw.param.filter(|value| !value.is_empty()),
        attack: raw.attack.filter(|value| !value.is_empty()),
        description: raw.description.filter(|value| !value.is_empty()),
        plugin_id: raw.plugin_id.filter(|value| !value.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use wiremock::Mock;
    use wiremock::MockServer;
    use wiremock::ResponseTemplate;
    use wiremock::matchers::method;
    use wiremock::matchers::path;
    use wiremock::matchers::query_param;

    #[tokio::test]
    async fn zap_client_runs_active_scan_and_collects_alerts() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/JSON/core/view/version/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "version": "2.16.1"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/core/action/accessUrl/"))
            .and(query_param("url", "http://127.0.0.1:8081"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/spider/action/scan/"))
            .and(query_param("url", "http://127.0.0.1:8081"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "scan": "3"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/spider/view/status/"))
            .and(query_param("scanId", "3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "100"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/ascan/action/scan/"))
            .and(query_param("url", "http://127.0.0.1:8081"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "scan": "4"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/ascan/view/status/"))
            .and(query_param("scanId", "4"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "100"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/alert/view/alerts/"))
            .and(query_param("baseurl", "http://127.0.0.1:8081"))
            .and(query_param("start", "0"))
            .and(query_param("count", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "alerts": [{
                    "alert": "Reflected XSS",
                    "risk": "High",
                    "confidence": "High",
                    "url": "http://127.0.0.1:8081/search?q=test",
                    "param": "q",
                    "attack": "<script>alert(1)</script>",
                    "description": "The application reflects untrusted input.",
                    "pluginId": "40012"
                }]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/JSON/core/view/urls/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "urls": [
                    "http://127.0.0.1:8081/",
                    "http://127.0.0.1:8081/search?q=test",
                    "http://example.com/offscope"
                ]
            })))
            .mount(&server)
            .await;

        let client = ZapClient::new(ZapClientConfig {
            base_url: server.uri(),
            api_key: None,
        });
        let result = client
            .run_scan(&ZapRunRequest {
                target: "http://127.0.0.1:8081".to_string(),
                scan_type: ZapScanType::Active,
                max_minutes: 1,
                max_alerts: 10,
            })
            .await
            .expect("ZAP scan should succeed");

        assert_eq!(
            result,
            ZapRunResult {
                target: "http://127.0.0.1:8081".to_string(),
                zap_base_url: server.uri(),
                version: "2.16.1".to_string(),
                scan_type: ZapScanType::Active,
                spider: Some(ZapScanProgress {
                    scan_id: "3".to_string(),
                    status: 100,
                }),
                active_scan: Some(ZapScanProgress {
                    scan_id: "4".to_string(),
                    status: 100,
                }),
                discovered_urls: vec![
                    "http://127.0.0.1:8081/".to_string(),
                    "http://127.0.0.1:8081/search?q=test".to_string(),
                ],
                alert_count: 1,
                alerts: vec![ZapAlertSummary {
                    name: "Reflected XSS".to_string(),
                    risk: "High".to_string(),
                    confidence: "High".to_string(),
                    url: "http://127.0.0.1:8081/search?q=test".to_string(),
                    param: Some("q".to_string()),
                    attack: Some("<script>alert(1)</script>".to_string()),
                    description: Some("The application reflects untrusted input.".to_string(),),
                    plugin_id: Some("40012".to_string()),
                }],
                alerts_truncated: false,
            }
        );
    }
}
