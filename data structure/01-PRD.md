# Product Requirements Document

## 1. Product vision
Build an AI engineering guardian that can understand a software system and help a development team safely improve its security, reliability, quality, test coverage, architecture, and maintainability.

## 2. Problem
Traditional scanners produce isolated findings. Developers still need to understand relationships between code, dependencies, architecture, tests, deployments, and business behavior. The Guardian correlates evidence and turns it into actionable engineering work.

## 3. Goals
- Deep project discovery and codebase mapping.
- Security and bug auditing.
- Dependency and supply-chain analysis.
- Production incident root-cause assistance.
- Change impact analysis.
- AI-generated QA scenarios and controlled execution.
- Safe fix planning and verification.
- Repeated audits and regression detection.
- Strong protection against prompt injection and unsafe tool use.

## 4. Non-goals
- Guaranteeing a project is 100% secure.
- Autonomous production deployment.
- Unrestricted shell access.
- Treating repository instructions as trusted policy.
- Blindly applying AI-generated patches.

## 5. Users
- Developer
- QA Engineer
- Security Engineer
- Tech Lead
- DevOps/SRE
- Project/Engineering Manager
- Administrator

## 6. Functional modules
### A. Project Discovery
Detect languages, frameworks, package managers, databases, containers, CI/CD, APIs, tests, configuration and entry points.

### B. Codebase Intelligence
Build file/module/dependency/API/data-flow maps and searchable project knowledge.

### C. Security & Bug Audit
Combine deterministic scanners, tests and AI reasoning. Findings contain severity, confidence, evidence, affected assets, remediation and verification criteria.

### D. Incident Investigator
Accept logs, stack traces, traces, metrics, deployment/change history and incident notes. Correlate evidence and rank hypotheses.

### E. Change Impact
Given a proposed change, identify affected code, APIs, schemas, integrations, tests, security controls and operational risks.

### F. QA
Generate risk-based test plans and execute only policy-approved tests.

### G. Supply Chain
Audit manifests, lockfiles, dependency vulnerabilities, suspicious package behavior, CI permissions, container configuration and secrets.

### H. Fix & Verify
Create patch plans, require approvals according to risk, apply controlled changes, test, independently verify and re-scan.

### I. Self-Audit
Guardian audits its own dependencies, policies, code, tools and security boundaries.

## 7. Outputs
- Executive report
- Technical report
- Finding list
- Risk score
- Dependency report
- Architecture map
- Change impact report
- QA plan/results
- Incident investigation report
- Fix plan/diff
- Verification report
- Audit trail

## 8. Success metrics
- Finding precision/false-positive rate
- Critical findings detected before release
- Verification success rate
- Regression rate
- Test coverage improvement
- Mean time to understand incidents
- Mean time to remediate approved issues
- Number of unsafe operations blocked
- Secret redaction success
- Prompt-injection test pass rate

## 9. MVP
Discovery + codebase map + security/bug/dependency/secret scan + structured findings + approval policy + safe fix suggestions + tests + verification + final report.
