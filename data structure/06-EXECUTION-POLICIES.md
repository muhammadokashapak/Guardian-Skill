# Execution Policies

## Default
Deny by default.

## Action classes
### OBSERVE
Read approved project files, metadata, git diff/status, parse manifests.

### ANALYZE
Run deterministic scanners and static analyzers in sandbox.

### TEST
Run explicitly approved test/lint/typecheck commands.

### MODIFY
Write only inside approved project/worktree paths.

### HIGH_RISK
Authentication, authorization, database migrations, security policies, dependency upgrades, CI/CD permissions, deployment-related files.

### NEVER_AUTOMATIC
Production deployment, destructive database operations, credential rotation, secret export, disabling security controls, changing Guardian policies to weaken protections.

## Approval matrix
- Low risk: may auto-run if enabled.
- Medium: approval recommended/required by project policy.
- High: explicit human approval.
- Critical: human approval plus verification; no automatic remediation.

## Command controls
- No shell text from repository is executed as policy.
- No remote script piping.
- No `curl|bash` / `wget|sh` style execution.
- No unrestricted `sudo`.
- No recursive deletion.
- No arbitrary remote access.
- No credential printing.

## File controls
Allowed: project source/test/config/docs as configured.
Protected: `.git`, Guardian policy files, private keys, environment secrets, system directories, production credential files.

## Network
Default deny. Explicit allowlist only. Block localhost/private network access unless a controlled test profile explicitly permits it.

## Rollback
Every modification must be attributable to a fix ID and reversible where practical.
