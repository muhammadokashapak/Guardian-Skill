# Guardian AI — Engineering Intelligence & Security Defense Platform

> **High-Security AI Engineering Intelligence, Codebase Mapping, Vulnerability Scanning, and Controlled Remediation Platform.**

Project Guardian safely analyzes codebases, detects architectural relationships, identifies security vulnerabilities, secret leaks, and dependency supply-chain risks, and facilitates human-approved, verified automated remediations.

---

## Architecture Overview

Guardian consolidates onto a unified, high-performance architecture:
- **Frontend Dashboard**: Next.js 14 + React 18 + TypeScript (Port 3000).
- **Core API Gateway**: Python FastAPI REST server with strict tenant scoping and RBAC (Port 8000).
- **Relational Persistence**: MySQL 8.0 (Containerized) / SQLite (Standalone local fallback) with 24 SQLAlchemy entities.
- **Queue & Async Worker**: Redis 7.x Queue Broker with dedicated `GuardianQueueWorker` process.
- **Engineering Intelligence & Scanners**: Codebase AST indexing, SAST, secret detection, prompt-injection defense, dependency auditing, Docker & CI/CD inspection.
- **Controlled Fix Engine**: Dynamic unified diff patch application, pre-patch backups, and independent re-scan verification.
- **Tamper-Evident Audit Trail**: SHA-256 cryptographic hash-chained audit logging.

```text
Next.js Frontend (:3000)
         │
         │ REST / HTTPS
         ▼
FastAPI API Gateway (:8000)
   ├── Authentication & Role-Based Access Control (RBAC)
   ├── Strict Multi-Tenant Organization Scoping
   ├── REST Endpoints (Projects, Scans, Findings, Fixes, Approvals, Reports)
   └── SQLAlchemy ORM (24 Relational Entities)
         │
         ├──────────────────────┬──────────────────────┐
         ▼                      ▼                      ▼
   MySQL 8.0 Relational    Redis Broker Queue    In-Memory Fallback
         │                      │
         └──────────────┬───────┘
                        ▼
            Dedicated Background Worker
            (python -m guardian_engine.worker)
                        │
                        ▼
               Guardian Core Engine
         ├── Codebase AST Discovery & Indexing
         ├── 6 Security Scanners (SAST, Secrets, Dependencies, Containers, CI/CD, Prompt Injection)
         ├── Disposable Git Worktree Sandbox
         ├── Dynamic Patch Applicator (Unified Diff)
         └── Independent Verification & Re-Scan
```

---

## Directory Organization

```text
Guardian-Skill/
├── guardian_engine/         # Core Python Security Engine, FastAPI API, & Background Worker
│   ├── core/                # Policy engine, sandbox, path security, secret redactor, audit logger
│   ├── codebase/            # Project discovery, AST indexer, architecture graph builder
│   ├── scanners/            # SAST, secret, dependency, Docker/CI, prompt injection scanners
│   ├── ai/                  # Multi-provider gateway (Ollama, OpenAI, Gemini, Claude, Offline)
│   ├── analyzers/           # Change impact, QA engine, incident investigator, supply chain, fix engine
│   ├── db/                  # SQLAlchemy 24-entity models and session manager (MySQL / SQLite)
│   ├── queue/               # JobManager with Redis connectivity and async pool fallback
│   ├── api/                 # Authoritative FastAPI REST API
│   └── worker.py            # Dedicated background queue worker process
├── frontend/                # Next.js 14 + React + TypeScript Dashboard
│   ├── src/app/             # 24 production views with dark mode engineering aesthetics
│   ├── src/lib/api.ts       # Type-safe API client talking to FastAPI (:8000)
│   └── src/app/globals.css  # Curated theme with glassmorphism and status badges
├── fixtures/                # Harmless security regression corpus & enterprise fixture
├── skills/guardian/         # Antigravity Skill definition and CLI tool
├── .agents/skills/guardian/ # Antigravity Workspace auto-discovery location
├── tests/                   # Full automated test suite (30 test cases passing)
├── docker-compose.yml       # Production orchestration (mysql, redis, api, worker, frontend)
├── .env.example             # Local standalone environment configuration
├── .env.docker.example      # Docker production environment configuration
├── data structure/          # Original specifications, blueprints, and archived legacy scaffolds
└── .github/workflows/       # Hardened CI/CD pipeline
```

---

## Quickstart & Local Development

### 1. Requirements
- Python 3.10+
- Node.js 18+ and npm

### 2. Install Dependencies
```bash
# Python dependencies
pip install -r requirements.txt

# Frontend dependencies
cd frontend
npm install
cd ..
```

### 3. Run Automated Tests
```bash
pytest -v
```
All 30 tests will execute, verifying database persistence, multi-tenant boundaries, security policies, secret redaction, and end-to-end workflows.

### 4. Run Core Services Locally
```bash
# Terminal 1: Launch FastAPI Gateway
uvicorn guardian_engine.api.app:app --host 0.0.0.0 --port 8000

# Terminal 2: Launch Next.js Dashboard
cd frontend
npm run dev

# Terminal 3 (Optional): Launch Background Worker
python -m guardian_engine.worker
```
- Dashboard: `http://localhost:3000`
- API Documentation: `http://localhost:8000/docs`

---

## Docker Production Deployment

To deploy the complete 5-service production stack:

```bash
docker compose up -d
```

Services initialized:
- `guardian_mysql`: MySQL 8.0 with persistent storage and healthchecks.
- `guardian_redis`: Redis alpine queue broker with healthchecks.
- `guardian_api`: FastAPI REST API on port 8000.
- `guardian_worker`: Dedicated Python queue worker.
- `guardian_frontend`: Next.js web dashboard on port 3000.

---

## Antigravity Skill CLI Workflows

```bash
# Understand and map codebase architecture
python skills/guardian/guardian_cli.py understand --path fixtures/e2e-enterprise-project

# Run full security and secret audit
python skills/guardian/guardian_cli.py scan --path fixtures/e2e-enterprise-project

# Assess change impact of a proposed modification
python skills/guardian/guardian_cli.py impact --path fixtures/e2e-enterprise-project --change "Refactor auth logic"

# Generate risk-based QA test plan and execute in sandbox
python skills/guardian/guardian_cli.py qa --feature "Core Feature"

# Investigate production incident logs
python skills/guardian/guardian_cli.py incident --logs "fixtures/incident_sample.log"

# Audit supply-chain manifests and lifecycle scripts
python skills/guardian/guardian_cli.py supply-chain --path fixtures/e2e-enterprise-project

# Run Guardian Self-Defense Audit
python skills/guardian/guardian_cli.py self-audit
```

---

## Security Model & Guardrails

1. **Untrusted Data Boundary**: All repository content (code, comments, READMEs, commit messages) is isolated as untrusted data. Embedded instructions (`Ignore instructions...`) are detected by `PromptInjectionScanner` and never executed.
2. **Deterministic Allowlist**: The `PolicyEngine` enforces a strict binary allowlist (`git`, `python`, `npm`, `pytest`, etc.) and rejects shell chaining metacharacters (`;`, `&&`, `|`, `` ` ``, `$`).
3. **Filesystem Canonicalization**: `PathSecurity` prevents directory traversal (`../`), symlink breakout, and unauthorized access to `.git`, `.env`, and private keys.
4. **Secret Redaction**: High-entropy keys (AWS, GitHub tokens, Slack webhooks/tokens, private keys) are redacted before logging or AI routing.
5. **Human Approval Gate**: All high-risk and modifying remediations require staff engineer authorization (`POST /api/v1/fixes/{id}/approve`).
6. **Unified Diff Patching & Rollback**: Fixes are applied via structured unified diffs with pre-patch backups, followed by automated re-scanning and instant rollback upon failure.
7. **Multi-Tenant Isolation**: Tenant context is extracted from authenticated API headers, strictly scoping all queries (`X-Organization-Id`) and preventing cross-tenant information leakage.

---

## 👨‍💻 Author & Connect

**Muhammad Okasha**  
*AI Systems & Full-Stack Software Architect*  
- **GitHub:** [@muhammadokashapak](https://github.com/muhammadokashapak)
- **Portfolio:** [Muhammad Okasha 3D Portfolio](https://github.com/muhammadokashapak/Portfolio-3D)

---

## 📄 License
This project is open-source and licensed under the [MIT License](LICENSE).
