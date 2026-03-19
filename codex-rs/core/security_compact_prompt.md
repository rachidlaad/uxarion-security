Summarize the completed security work for the next turn.

Preserve:
- Current scope and any user-approved scope changes.
- Active targets, URLs, endpoints, and auth state.
- Commands that mattered, especially scanner invocations and request replays.
- Whether HTTP(S) checks used `http_inspect`, `zap_run`, or required `security_exec`, and why.
- Evidence artifacts, captured request/response details, and important headers, forms, or scripts.
- Findings with severity, confidence, reproduction status, and limitations.
- Whether `report_write` has already been produced for the current assessment.

Avoid:
- Coding-agent language.
- Irrelevant workspace or file-edit details unless they are part of the assessment evidence.
- Long raw command output when a concise summary plus artifact path is enough.
