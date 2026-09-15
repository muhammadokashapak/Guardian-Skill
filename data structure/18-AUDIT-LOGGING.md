# Audit Logging & Observability

## Log
- authentication/authorization decisions
- policy decisions
- tool execution requests/results
- scans
- findings
- approvals
- patches
- tests
- verification
- reports
- configuration changes

## Redaction
Apply secret redaction before persistence. Do not log environment dumps, credentials, private keys or full authorization headers.

## Integrity
Audit records should be append-oriented and protected from ordinary project-level modification.

## Correlation
Use request_id / scan_id / fix_id / verification_id to connect events.

## Metrics
- scan duration
- scanner failures
- blocked commands
- findings by severity
- fix success/failure
- verification success
- false-positive feedback
- policy violations
