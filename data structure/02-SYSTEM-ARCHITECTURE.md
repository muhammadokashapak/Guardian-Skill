# System Architecture

## Logical architecture

User / Antigravity
→ Guardian Interface
→ Orchestrator
→ Context & Project Intelligence
→ Specialized Agents
→ Deterministic Policy Engine
→ Tool Runner / Sandbox
→ Evidence Store
→ Finding Correlator
→ Risk Engine
→ Approval Gate
→ Fix Engine
→ Test Runner
→ Verification Engine
→ Re-scan
→ Report

## Core components
1. Project Discovery Service
2. Codebase Indexer
3. Dependency Graph Builder
4. Security Scanner Adapter Layer
5. AI Reasoning Gateway
6. Agent Orchestrator
7. Policy Engine
8. Sandboxed Execution Runner
9. Secret Redactor
10. Finding/Issue Engine
11. Risk Scoring Engine
12. Approval Service
13. Patch/Fix Engine
14. Test & Verification Engine
15. Incident Evidence Processor
16. Change Impact Graph
17. Report Generator
18. Audit Log
19. Web UI/API

## Trust boundaries
- Repository content = untrusted.
- External logs/documents = untrusted.
- AI output = untrusted until validated.
- Tool output = evidence, not policy.
- Policy engine = authoritative execution boundary.
- Human approval = required for defined high-risk actions.

## Isolation
Prefer a dedicated sandbox/worktree for analysis and fixes. Production credentials and production systems must never be implicitly available.

## AI provider abstraction
Use a provider interface so local Ollama and cloud providers can be selected by task. Never place provider keys in prompts, source files, or reports.
