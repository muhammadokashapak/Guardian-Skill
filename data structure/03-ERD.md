# ERD / Data Model

## Main entities
- users
- organizations
- projects
- project_repositories
- project_snapshots
- scans
- findings
- finding_evidence
- dependencies
- dependency_risks
- incidents
- incident_evidence
- change_requests
- change_impacts
- test_plans
- test_cases
- test_runs
- fixes
- approvals
- verification_runs
- policies
- tool_executions
- audit_events
- reports
- ai_runs

## Relationships
- organization 1→N users
- organization 1→N projects
- project 1→N repositories
- project 1→N snapshots
- project 1→N scans
- scan 1→N findings
- finding 1→N evidence
- project 1→N dependencies
- dependency 1→N dependency_risks
- project 1→N incidents
- incident 1→N incident_evidence
- project 1→N change_requests
- change_request 1→N change_impacts
- project 1→N test_plans
- test_plan 1→N test_cases
- test_case 1→N test_runs
- finding 1→N fixes
- fix 1→N approvals
- fix 1→N verification_runs
- project 1→N tool_executions
- project 1→N audit_events
- project 1→N reports
- project 1→N ai_runs

## Required design rules
- Every tenant-owned record carries organization_id.
- Every project-scoped record carries project_id directly or through a controlled parent.
- Store immutable audit events.
- Store hashes/version identifiers for analyzed snapshots.
- Never store raw secrets as finding evidence.
- Soft deletion must not erase audit records.

## Suggested key fields
### projects
id, organization_id, name, repository_type, default_branch, risk_profile, status, created_at

### scans
id, project_id, snapshot_id, scan_type, status, started_at, finished_at, engine_version

### findings
id, scan_id, fingerprint, category, severity, confidence, status, title, summary, affected_path, line_start, line_end, remediation

### approvals
id, fix_id, requested_by, approved_by, risk_level, decision, reason, created_at

### tool_executions
id, project_id, tool_name, command_class, policy_decision, exit_code, started_at, finished_at, redacted_output

### audit_events
id, organization_id, project_id, actor_type, actor_id, event_type, target_type, target_id, metadata_json, created_at
