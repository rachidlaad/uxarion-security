---
name: "security-reporting"
description: "Use when the user asks to draft, rewrite, polish, or regenerate a pentest or security assessment report from saved Uxarion session artifacts such as findings, evidence files, screenshots, and prior report drafts. Build reports from persisted artifacts, not memory alone, and save the final Markdown with `report_write`."
---

# Security Reporting

Draft grounded pentest reports from saved Uxarion session artifacts.

Use this skill when the user asks for:

- a full session report
- a finding-specific report
- a bug bounty style writeup
- a cleaner or more polished final report from saved evidence

## Quick start

1. Treat the request as a reporting step, not a new testing step.
2. Read only the relevant saved artifacts from the session directory provided in the user request.
3. Start with `findings.json` and `state.json`.
4. Inspect referenced evidence files with security-mode-allowed local file-inspection tools such as `grep`, `sed`, or `awk` when needed.
5. If evidence includes screenshots or image files, inspect them with `view_image`.
6. Load `references/report-structure.md`.
7. Also load one style reference:
   - `references/pentest-report-style.md` for general pentest/client reporting
   - `references/bug-bounty-report-style.md` for bug bounty style reports
8. Save the final Markdown with `report_write` using the `content` field.
9. After writing the file, tell the user the exact `report_path`.

## Workflow

1. Confirm the report scope from the user request:
   - entire session
   - single finding
   - bug bounty style vs general pentest style
2. Read the saved findings and session state from the provided paths.
3. Inspect only the evidence needed to support the requested report scope.
4. Reconcile claims against evidence before writing:
   - do not invent findings, severity, impact, or reproduction details
   - mark uncertainty clearly when evidence is partial
   - prefer supported claims over polished speculation
5. Write a clear Markdown report that follows `references/report-structure.md`.
6. Save it with `report_write`:
   - always provide `content`
   - provide `finding_id` only when writing a single-finding artifact
7. In the final response:
   - summarize what was written
   - include the exact `report_path`

## Rules

- Do not perform new network probing, scanning, or scope expansion unless the user explicitly asks to continue testing.
- Prefer persisted artifacts over memory or inference.
- Keep reproduction steps concrete and evidence-backed.
- Keep authorization/scope wording explicit when relevant.
- If no findings exist, write a truthful minimal report rather than inventing issues.
- In security mode, prefer direct reads from the provided absolute paths with `sed`, `grep`, or `awk`.
- Do not use relative paths for report artifacts. Use the provided absolute paths exactly.
- Do not use `ls`, `echo`, `printf`, nested shells, or `scope_validate` for local report artifacts; the provided file paths are already the allowed inputs for this reporting step.
- If you need to read multiple files, run one or more plain `sed`, `grep`, or `awk` commands against those absolute paths directly instead of adding shell formatting helpers.

## Good command shapes

- `sed -n '1,220p' /abs/path/findings.json /abs/path/state.json`
- `awk 'NR<=120 { print }' /abs/path/evidence.txt`

## Bad command shapes

- `scope_validate` on local file paths
- `echo ...; sed ...`
- `printf ...; sed ...`
- `bash -lc ...`
- `sed ... findings.json` when only an absolute path was provided

## Reference map

- `references/report-structure.md` -> required section layout and artifact expectations
- `references/pentest-report-style.md` -> tone and structure for general pentest/client reporting
- `references/bug-bounty-report-style.md` -> tone and structure for bug bounty style writeups
