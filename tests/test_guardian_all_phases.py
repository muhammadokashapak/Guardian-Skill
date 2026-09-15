import os
import sys
import shutil
import pytest
from pathlib import Path

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath("."))

from guardian_engine.core import (
    PolicyEngine, PathSecurity, PathSecurityError, SecretRedactor,
    SandboxedRunner, AuditLogger, ActionClass, PolicyDecision,
    RiskLevel, FindingSeverity, FindingStatus, Project
)
from guardian_engine.codebase import (
    ProjectDiscoveryService, CodebaseIndexer, GraphBuilder
)
from guardian_engine.scanners import (
    ScanManager, SecretScanner, SASTScanner,
    DependencyScanner, DockerAndCIScanner, PromptInjectionScanner
)
from guardian_engine.ai import AIRouter, MockOfflineAIProvider
from guardian_engine.analyzers import (
    ChangeImpactAnalyzer, QAEngine, IncidentInvestigator,
    SupplyChainGuardian, FixEngine, VerificationEngine
)
from guardian_engine.api.app import app
from fastapi.testclient import TestClient

client = TestClient(app)

# ==========================================
# PHASE 1: FOUNDATION & MODELS
# ==========================================
def test_phase01_foundation():
    project = Project(name="Test Proj", root_path="fixtures/01-vulnerable-web-app")
    assert project.id is not None
    assert project.organization_id == "org-default"
    assert project.risk_profile == RiskLevel.MEDIUM

# ==========================================
# PHASE 2: SECURITY BOUNDARY & POLICY ENGINE
# ==========================================
def test_phase02_security_boundary_and_policy():
    engine = PolicyEngine()

    # 1. Deny forbidden binaries
    decision, reason = engine.validate_command(["powershell", "-c", "rmdir"])
    assert decision == PolicyDecision.DENY

    # 2. Deny shell chaining
    decision, reason = engine.validate_command(["python", "test.py; rm -rf /"])
    assert decision == PolicyDecision.DENY

    # 3. Deny NEVER_AUTOMATIC
    decision, reason = engine.evaluate_action(
        ActionClass.NEVER_AUTOMATIC,
        "deploy_production"
    )
    assert decision == PolicyDecision.DENY

    # 4. Require approval for HIGH_RISK
    decision, reason = engine.evaluate_action(
        ActionClass.HIGH_RISK,
        "ModifyAuthentication",
        is_human_approved=False
    )
    assert decision == PolicyDecision.REQUIRE_APPROVAL

    # 5. Path Security - Prevent directory traversal escape
    with pytest.raises(PathSecurityError):
        PathSecurity.canonicalize_and_validate("fixtures", "../../windows/system32")

    # 6. Secret Redaction
    sample = "AWS key is AKIA1111222233334444 and secret is safe"
    redacted, findings = SecretRedactor.redact(sample)
    assert "AKIA1111222233334444" not in redacted
    assert "[REDACTED_AWS_ACCESS_KEY]" in redacted

    # 7. Tamper-evident Audit Logger
    logger = AuditLogger()
    logger.record_event(
        event_type="TEST_EVENT",
        target_type="SYSTEM",
        target_id="sys-1"
    )
    assert logger.verify_integrity() is True

# ==========================================
# PHASE 3: PROJECT DISCOVERY
# ==========================================
def test_phase03_discovery():
    discovery_svc = ProjectDiscoveryService()
    profile = discovery_svc.discover("fixtures/01-vulnerable-web-app")
    assert "JavaScript" in profile.languages
    assert "Express" in profile.frameworks
    assert "npm" in profile.package_managers
    assert profile.tree_hash is not None

# ==========================================
# PHASE 4: CODEBASE INTELLIGENCE
# ==========================================
def test_phase04_codebase_intelligence():
    indexer = CodebaseIndexer()
    index = indexer.index_directory("fixtures/01-vulnerable-web-app")
    assert "app.js" in index
    assert index["app.js"].language == "JavaScript"

    graph = GraphBuilder.build_from_index(index)
    assert len(graph.nodes) > 0
    # Check affected query
    affected = graph.query_affected_by_file("app.js")
    assert isinstance(affected, list)

# ==========================================
# PHASE 5: SCANNING & FINDINGS NORMALIZATION
# ==========================================
def test_phase05_scanning_engine():
    logger = AuditLogger()
    scan_mgr = ScanManager(logger)

    # Scan fixture 01 (Vulnerable Web App: SQLi + XSS)
    findings = scan_mgr.run_full_scan("proj-1", "fixtures/01-vulnerable-web-app")
    assert len(findings) >= 2
    categories = [f.category for f in findings]
    assert "INJECTION" in categories or "XSS" in categories

    # Verify stable fingerprint
    fp1 = findings[0].fingerprint
    findings_rescan = scan_mgr.run_full_scan("proj-1", "fixtures/01-vulnerable-web-app")
    assert any(f.fingerprint == fp1 for f in findings_rescan)

# ==========================================
# PHASE 6: MULTI-AGENT ORCHESTRATION & AI GATEWAY
# ==========================================
def test_phase06_ai_gateway():
    router = AIRouter(default_provider="mock-offline")
    resp = router.reason(
        task_instruction="Audit this SQL injection",
        untrusted_context="const sql = `SELECT * FROM users WHERE id = '${id}'`;"
    )
    assert resp.content is not None
    assert "Root Cause" in resp.content or "Remediation" in resp.content

# ==========================================
# PHASE 7: CHANGE IMPACT ANALYZER
# ==========================================
def test_phase07_change_impact():
    router = AIRouter(default_provider="mock-offline")
    analyzer = ChangeImpactAnalyzer(router)
    indexer = CodebaseIndexer()
    index = indexer.index_directory("fixtures/01-vulnerable-web-app")
    graph = GraphBuilder.build_from_index(index)

    report = analyzer.analyze(graph, "Modify user auth table and drop column", "app.js")
    assert report.migration_required is True
    assert "app.js" in report.target_files
    assert report.deployment_risk in ["MEDIUM", "HIGH"]

# ==========================================
# PHASE 8: AI QA ENGINEER
# ==========================================
def test_phase08_qa_engine():
    router = AIRouter(default_provider="mock-offline")
    runner = SandboxedRunner(".")
    qa = QAEngine(runner, router)

    plan = qa.generate_plan("User Login", "auth context")
    assert len(plan.test_cases) >= 3

    result = qa.execute_plan(plan)
    assert result.total_tests == len(plan.test_cases)
    assert result.verdict == "PASS"

# ==========================================
# PHASE 9: INCIDENT INVESTIGATOR
# ==========================================
def test_phase09_incident_investigator():
    router = AIRouter(default_provider="mock-offline")
    investigator = IncidentInvestigator(router)

    sample_logs = """
2026-09-15 10:00:01 [ERROR] NullPointerException at AuthController.php:45
2026-09-15 10:00:02 [ERROR] Call to a member function getRole() on null
"""
    rep = investigator.investigate("inc-100", "Production 500 error in auth", sample_logs)
    assert len(rep.hypotheses) > 0
    assert rep.hypotheses[0].confidence > 0.8
    assert "null" in rep.probable_root_cause.lower()

# ==========================================
# PHASE 10: SUPPLY CHAIN SECURITY
# ==========================================
def test_phase10_supply_chain():
    guardian = SupplyChainGuardian()
    report = guardian.audit("fixtures/05-dependency-risk")
    assert report.total_dependencies > 0

# ==========================================
# PHASE 11 & 12: FIX ENGINE & VERIFICATION (ISOLATED WORKTREE)
# ==========================================
def test_phase11_and_12_fix_and_verify(tmp_path):
    # Copy fixture 01 to disposable worktree to isolate patch mutation
    worktree = tmp_path / "worktree"
    shutil.copytree("fixtures/01-vulnerable-web-app", worktree)

    logger = AuditLogger()
    engine = PolicyEngine()
    router = AIRouter(default_provider="mock-offline")
    scan_mgr = ScanManager(logger)
    fix_engine = FixEngine(engine, logger, router)
    verify_engine = VerificationEngine(scan_mgr, logger)

    findings = scan_mgr.run_full_scan("proj-fix", str(worktree))
    target_finding = [f for f in findings if f.category == "INJECTION"][0]

    # Create Fix Plan
    plan = fix_engine.create_fix_plan(target_finding, str(worktree))
    assert plan.diff is not None
    assert plan.requires_approval is True

    # Policy blocks unauthorized modification
    assert fix_engine.apply_fix_plan(plan, str(worktree), is_human_approved=False) is False

    # Apply with explicit human approval
    assert fix_engine.apply_fix_plan(plan, str(worktree), is_human_approved=True) is True

    # Verification run confirms resolution in worktree
    ver_res = verify_engine.verify_and_rescan(plan, target_finding, str(worktree))
    assert ver_res.plan_id == plan.id
    assert ver_res.original_resolved is True

# ==========================================
# PHASE 13: UI & API ENDPOINTS
# ==========================================
def test_phase13_rest_api():
    res = client.get("/api/v1/system-health")
    assert res.status_code == 200
    assert res.json()["status"] == "HEALTHY"

    # Create project
    p_res = client.post("/api/v1/projects", json={
        "name": "API Fixture Proj",
        "root_path": "fixtures/01-vulnerable-web-app"
    })
    assert p_res.status_code == 201
    p_id = p_res.json()["id"]

    # Start Scan
    s_res = client.post(f"/api/v1/projects/{p_id}/scans")
    assert s_res.status_code == 200
    assert len(s_res.json()["findings"]) > 0

    # Get Audit Events
    aud_res = client.get("/api/v1/audit-events")
    assert aud_res.status_code == 200
    assert aud_res.json()["integrity_verified"] is True

# ==========================================
# PHASE 14: GUARDIAN SELF-AUDIT
# ==========================================
def test_phase14_self_audit():
    res = client.post("/api/v1/self-audit")
    assert res.status_code == 200
    data = res.json()
    assert data["prompt_injection_containment"] == "PASS"
    assert data["symlink_escape_blocking"] == "PASS"
    assert data["secret_redaction_accuracy"] == "PASS"
    assert data["verdict"] == "SECURE"

# ==========================================
# PHASE 15: END-TO-END DEMONSTRATION
# ==========================================
def test_phase15_end_to_end_demonstration(tmp_path):
    """
    Validates complete flow:
    Import -> Discover -> Index -> Scan -> Finding -> AI -> Fix Plan -> Approval -> Verification -> Audit
    """
    worktree = tmp_path / "e2e_worktree"
    shutil.copytree("fixtures/06-fake-secrets", worktree)

    logger = AuditLogger()
    scan_mgr = ScanManager(logger)
    router = AIRouter()
    policy = PolicyEngine()
    fix_eng = FixEngine(policy, logger, router)
    verify_eng = VerificationEngine(scan_mgr, logger)

    findings = scan_mgr.run_full_scan("e2e-proj", str(worktree))
    assert len(findings) > 0

    finding = findings[0]
    plan = fix_eng.create_fix_plan(finding, str(worktree))
    assert plan.approved is False

    # Blocked without approval
    blocked = fix_eng.apply_fix_plan(plan, str(worktree), is_human_approved=False)
    assert blocked is False

    # Approved and applied
    applied = fix_eng.apply_fix_plan(plan, str(worktree), is_human_approved=True)
    assert applied is True

    # Audit chain check
    assert logger.verify_integrity() is True
