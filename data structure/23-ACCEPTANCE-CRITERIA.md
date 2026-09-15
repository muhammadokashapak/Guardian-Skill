# Global Acceptance Criteria

The platform is acceptable for MVP when:

1. It can discover and classify a supported project.
2. It produces a reproducible scan record.
3. It detects and reports configured security/dependency/secret checks.
4. Findings have severity, confidence, evidence and remediation.
5. Repository prompt injection cannot override policy.
6. Dangerous commands are blocked by deterministic policy.
7. Secrets are redacted from reports/logs.
8. High-risk fixes require explicit approval.
9. Applied fixes produce auditable diffs.
10. Tests run before verification.
11. Verification does not rely solely on the same AI statement that proposed the fix.
12. Re-scan can confirm or reject resolution.
13. Guardian self-audit tests pass.
14. Organization/project authorization is enforced server-side.
