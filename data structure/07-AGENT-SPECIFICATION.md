# Agent Specification

## Guardian Orchestrator
Responsibilities:
- Build plan
- Select agents
- Gather evidence
- Correlate findings
- Enforce workflow
- Never bypass policy

## Security Agent
Inputs: source/config/scanner evidence.
Outputs: security findings, severity, confidence, evidence, remediation.

## Bug Agent
Finds logic/functional issues and distinguishes evidence from hypotheses.

## Dependency Agent
Inventories dependencies, lockfiles, versions and known risks.

## Codebase Intelligence Agent
Builds architecture/module/API/data-flow understanding and answers codebase questions.

## Incident Agent
Correlates logs, traces, metrics, deployment history and code changes. Produces ranked hypotheses, not unsupported certainty.

## Change Impact Agent
Maps requested change to affected components, tests, APIs, schemas, integrations and risks.

## QA Agent
Generates risk-based tests and selects safe execution commands.

## Verification Agent
Independently evaluates whether a fix satisfies the finding's acceptance criteria and whether regressions were introduced.

## Policy Guardian
Not an LLM-only agent. It is a deterministic authorization layer that validates every tool/action request.

## Agent output contract
Every agent must return structured data:
- task_id
- evidence[]
- conclusions[]
- confidence
- recommended_actions[]
- blocked_actions[]
- unresolved_questions[]
