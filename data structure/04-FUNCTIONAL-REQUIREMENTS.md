# Functional Requirements

## FR-001 Project onboarding
User can add a repository/workspace and select analysis scope.

## FR-002 Stack detection
System detects supported languages/frameworks/package managers/databases/CI.

## FR-003 Snapshotting
Each scan references an immutable snapshot/hash where practical.

## FR-004 Codebase graph
System maps files, modules, imports, APIs, data models, dependencies and tests.

## FR-005 Security audit
System runs configured security checks and correlates evidence.

## FR-006 Bug audit
System identifies likely functional/logic defects with evidence and confidence.

## FR-007 Dependency audit
System inventories dependencies and risk.

## FR-008 Secret detection
System detects probable secrets and redacts values.

## FR-009 Incident analysis
User can submit incident evidence and receive ranked hypotheses.

## FR-010 Change impact
User can describe a proposed change and receive affected-area analysis.

## FR-011 QA generation
System creates test plans/cases from requirements, code and risk.

## FR-012 Controlled execution
Only policy-approved tools/actions may execute.

## FR-013 Approval workflow
Risk-sensitive fixes require explicit approval.

## FR-014 Fix proposal
System produces structured fix plans/diffs.

## FR-015 Verification
Every applied fix gets tests and independent verification.

## FR-016 Re-scan
Resolved findings are re-evaluated after changes.

## FR-017 Reports
Generate executive and technical reports.

## FR-018 Audit trail
Every meaningful action and policy decision is recorded.

## FR-019 Self-audit
Guardian can audit its own implementation and configuration.

## FR-020 Continuous mode
Optional future mode watches approved repository changes and schedules re-audits.
