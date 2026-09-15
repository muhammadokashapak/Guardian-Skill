# API Specification

## Authentication
Use the host application's authentication. Never expose AI provider keys to clients.

## Core endpoints
POST /api/v1/projects
GET /api/v1/projects/{id}
POST /api/v1/projects/{id}/scans
GET /api/v1/scans/{id}
GET /api/v1/projects/{id}/findings
POST /api/v1/findings/{id}/fix-plan
POST /api/v1/fixes/{id}/approve
POST /api/v1/fixes/{id}/apply
POST /api/v1/fixes/{id}/verify
POST /api/v1/projects/{id}/impact-analysis
POST /api/v1/projects/{id}/incidents
POST /api/v1/incidents/{id}/investigate
POST /api/v1/projects/{id}/qa/plans
POST /api/v1/qa/runs
GET /api/v1/projects/{id}/reports
POST /api/v1/self-audit

## API rules
- Validate every input.
- Authorize organization/project access server-side.
- Rate-limit expensive operations.
- Never accept a raw shell command as an authorization token.
- Redact secrets in API responses.
- Use idempotency keys for mutation endpoints.
