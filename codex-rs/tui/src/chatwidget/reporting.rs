use codex_protocol::ThreadId;
use serde::Deserialize;
use std::path::Path;
use std::path::PathBuf;

pub(super) const SECURITY_REPORTING_SKILL_NAME: &str = "security-reporting";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ReportCommandScope {
    All,
    Finding(String),
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct PersistedFinding {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub vulnerability: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedReportRequest {
    pub session_dir: PathBuf,
    pub findings_path: PathBuf,
    pub state_path: PathBuf,
    pub evidence_dir: PathBuf,
    pub report_structure_path: PathBuf,
    pub pentest_style_path: PathBuf,
    pub bug_bounty_style_path: PathBuf,
    pub target_report_path: PathBuf,
}

pub(super) fn parse_report_scope(args: &str) -> Result<ReportCommandScope, String> {
    let trimmed = args.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
        return Ok(ReportCommandScope::All);
    }

    let mut parts = trimmed.split_whitespace();
    let command = parts.next();
    let maybe_id = parts.next();
    let extra = parts.next();

    if matches!(command, Some(value) if value.eq_ignore_ascii_case("finding"))
        && let Some(id) = maybe_id
        && extra.is_none()
    {
        return Ok(ReportCommandScope::Finding(id.to_string()));
    }

    Err("Usage: /report [all|finding <id>]".to_string())
}

pub(super) fn security_session_dir(
    codex_home: &Path,
    thread_id: Option<ThreadId>,
) -> Option<PathBuf> {
    thread_id.map(|id| codex_home.join("security").join(id.to_string()))
}

pub(super) fn load_findings(
    codex_home: &Path,
    thread_id: Option<ThreadId>,
) -> Result<Vec<PersistedFinding>, String> {
    let Some(session_dir) = security_session_dir(codex_home, thread_id) else {
        return Ok(Vec::new());
    };

    let findings_path = session_dir.join("findings.json");
    if !findings_path.exists() {
        return Ok(Vec::new());
    }

    let bytes = std::fs::read(&findings_path).map_err(|err| {
        format!(
            "Failed to read findings from {}: {err}",
            findings_path.display()
        )
    })?;
    let mut findings: Vec<PersistedFinding> = serde_json::from_slice(&bytes).map_err(|err| {
        format!(
            "Failed to parse findings from {}: {err}",
            findings_path.display()
        )
    })?;

    for index in 0..findings.len() {
        if findings[index].id.trim().is_empty() {
            findings[index].id = format!("finding-{:04}", index + 1);
        }
    }

    Ok(findings)
}

pub(super) fn security_reporting_skill_path(codex_home: &Path) -> PathBuf {
    codex_home
        .join("skills")
        .join(".system")
        .join(SECURITY_REPORTING_SKILL_NAME)
        .join("SKILL.md")
}

pub(super) fn resolve_report_request(
    codex_home: &Path,
    thread_id: ThreadId,
    scope: &ReportCommandScope,
) -> Result<ResolvedReportRequest, String> {
    let session_dir = codex_home.join("security").join(thread_id.to_string());
    if !session_dir.is_dir() {
        return Err(
            "No persisted security session artifacts were found for this thread yet. Run an assessment first, then try /report again."
                .to_string(),
        );
    }

    let findings_path = session_dir.join("findings.json");
    if !findings_path.is_file() {
        return Err(format!(
            "Cannot generate a report yet because {} is missing. Record findings in this session first, then try /report again.",
            findings_path.display()
        ));
    }

    let state_path = session_dir.join("state.json");
    if !state_path.is_file() {
        return Err(format!(
            "Cannot generate a report yet because {} is missing. Run an assessment that saves session state first, then try /report again.",
            state_path.display()
        ));
    }

    let evidence_dir = session_dir.join("evidence");
    let report_path = match scope {
        ReportCommandScope::All => session_dir.join("report.md"),
        ReportCommandScope::Finding(id) => session_dir.join(format!("report-finding-{id}.md")),
    };
    let skill_dir = codex_home
        .join("skills")
        .join(".system")
        .join(SECURITY_REPORTING_SKILL_NAME);
    let report_structure_path = skill_dir.join("references").join("report-structure.md");
    let pentest_style_path = skill_dir.join("references").join("pentest-report-style.md");
    let bug_bounty_style_path = skill_dir
        .join("references")
        .join("bug-bounty-report-style.md");
    for required_path in [
        &report_structure_path,
        &pentest_style_path,
        &bug_bounty_style_path,
    ] {
        if !required_path.is_file() {
            return Err(format!(
                "Cannot generate a report because the reporting skill reference {} is missing.",
                required_path.display()
            ));
        }
    }

    if let ReportCommandScope::Finding(id) = scope {
        let findings = load_findings(codex_home, Some(thread_id))?;
        if findings.iter().all(|finding| finding.id != *id) {
            return Err(format!(
                "Cannot generate a report for `{id}` because that finding was not recorded in this session."
            ));
        }
    }

    Ok(ResolvedReportRequest {
        session_dir,
        findings_path,
        state_path,
        evidence_dir,
        report_structure_path,
        pentest_style_path,
        bug_bounty_style_path,
        target_report_path: report_path,
    })
}

pub(super) fn build_report_request_prompt(
    resolved: &ResolvedReportRequest,
    scope: &ReportCommandScope,
) -> String {
    let scope_line = match scope {
        ReportCommandScope::All => "Report scope: all recorded findings.".to_string(),
        ReportCommandScope::Finding(id) => {
            format!("Report scope: only finding `{id}`.")
        }
    };
    let save_line = match scope {
        ReportCommandScope::All => {
            "Save the final Markdown with `report_write` using `content`.".to_string()
        }
        ReportCommandScope::Finding(id) => format!(
            "Save the final Markdown with `report_write` using `content` and `finding_id` set to `{id}`."
        ),
    };

    format!(
        "Use $security-reporting to write a Markdown security report from this Uxarion session's saved artifacts.\n\
Work only from persisted artifacts for this /report request; do not run new network tests or expand scope.\n\
For local file inspection in security mode, use direct reads with `sed`, `grep`, or `awk` on the provided absolute paths. Do not use relative paths, `ls`, `echo`, `printf`, or `scope_validate` for these local report artifacts.\n\
\n\
- session_dir: {}\n\
- findings_path: {}\n\
- state_path: {}\n\
- evidence_dir: {}\n\
- report_structure_path: {}\n\
- pentest_style_path: {}\n\
- bug_bounty_style_path: {}\n\
- target_report_path: {}\n\
- {}\n\
\n\
Inspect only the artifacts you need, then {} After writing the file, tell me the exact `report_path`.",
        resolved.session_dir.display(),
        resolved.findings_path.display(),
        resolved.state_path.display(),
        resolved.evidence_dir.display(),
        resolved.report_structure_path.display(),
        resolved.pentest_style_path.display(),
        resolved.bug_bounty_style_path.display(),
        resolved.target_report_path.display(),
        scope_line,
        save_line,
    )
}

pub(super) fn format_findings_summary(findings: &[PersistedFinding]) -> String {
    if findings.is_empty() {
        return "No findings have been recorded yet.".to_string();
    }

    let mut lines = vec![format!("{} finding(s):", findings.len())];
    for finding in findings {
        lines.push(format!(
            "- [{}] {} on {} [{} / {} / {}]",
            finding.id,
            finding.vulnerability,
            finding.target,
            finding.severity,
            finding.confidence,
            finding.status
        ));
    }
    lines.join("\n")
}
