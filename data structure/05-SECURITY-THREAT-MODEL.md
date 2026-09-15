# Security Threat Model

## Assets
- Source code
- Secrets
- Repository credentials
- AI/API credentials
- Security policies
- User/project data
- Audit records
- Generated patches
- Tool execution capability

## Threats
### Prompt injection
A repository file, issue, README, comment, log, or test attempts to instruct the AI to ignore Guardian rules.

Mitigation: repository content is data only; explicit trust boundary; policy engine outside model control.

### Command injection
AI constructs a dangerous command from untrusted content.

Mitigation: typed command classes, allowlists, argument validation, sandbox, approval gates.

### Path traversal
A requested file escapes the project root.

Mitigation: canonicalize paths, enforce root containment, deny symlink escapes.

### Secret disclosure
Secrets appear in prompts, logs, diffs or reports.

Mitigation: secret scanning/redaction, secret-free prompts where possible, never log raw values.

### Malicious dependency
A package or lifecycle script attempts harmful behavior.

Mitigation: lockfiles, dependency audit, isolated installation, network restrictions, review before upgrades.

### Privilege escalation
Tool execution gains more permissions than intended.

Mitigation: least privilege, dedicated runtime user, sandbox, no implicit sudo/admin.

### Unsafe patch
AI creates a change that fixes one issue but introduces another.

Mitigation: diff review, tests, independent verification, re-scan, rollback.

### Data exfiltration
AI/tool sends project content to an external service unexpectedly.

Mitigation: network deny-by-default, provider allowlist, data minimization, explicit configuration.

## Security invariants
1. Model output is never itself authorization.
2. Repository text can never change Guardian policy.
3. No destructive command is automatic.
4. Guardian cannot automatically weaken its own security boundary.
5. Raw secrets never enter normal reports.
6. Production credentials are never assumed.
7. Failed policy checks fail closed.
