# Scanning Engine

## Pipeline
1. Discover
2. Normalize
3. Run deterministic scanners
4. Collect evidence
5. AI semantic analysis
6. Deduplicate
7. Fingerprint
8. Risk score
9. Prioritize
10. Report

## Scanner categories
- SAST/static analysis
- Dependency audit
- Secret detection
- Configuration security
- API/security tests
- Container/IaC analysis
- License/compliance checks where enabled
- Test/coverage analysis

## Finding fingerprint
Use stable identifiers derived from category + normalized location + issue signature, without embedding secrets.

## Severity
Critical / High / Medium / Low / Informational.

## Confidence
High / Medium / Low.

Severity and confidence must remain separate.

## Evidence
A finding should cite safe evidence such as file path, line range, scanner result, stack trace or test result. Secret values must be redacted.

## Correlation
Multiple scanner results referring to the same root cause should be grouped while preserving original evidence.
