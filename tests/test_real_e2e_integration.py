import os
import sys
import time
import uuid
import shutil
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath("."))

from guardian_engine.db.database import SessionLocal, init_db
from guardian_engine.db.models import Organization, User, Project, Finding, Fix, Approval, Scan
from guardian_engine.api.app import app

client = TestClient(app)

@pytest.fixture(scope="module", autouse=True)
def init_environment():
    init_db()

def test_full_integrated_e2e_workflow(tmp_path):
    """
    Executes the true end-to-end integration lifecycle:
    Organization -> Project -> Async Scan -> Database Persistence -> Finding Inspection
    -> Fix Plan -> Approval Gating -> Patching -> Verification -> Audit Verification
    -> Cross-Tenant Denial.
    """
    # 1. Setup isolated test worktree from enterprise fixture
    worktree = tmp_path / "enterprise_app"
    shutil.copytree("fixtures/e2e-enterprise-project", worktree)

    db = SessionLocal()
    org_slug = f"acme-{uuid.uuid4().hex[:6]}"
    org = Organization(name="Acme Corporation", slug=org_slug)
    db.add(org)
    db.commit()
    db.refresh(org)
    org_id = org.id
    db.close()

    headers = {"X-Organization-Id": org_id}

    # 2. Create Project via API
    create_proj_res = client.post(
        "/api/v1/projects",
        json={"name": "Enterprise Portal", "root_path": str(worktree)},
        headers=headers
    )
    assert create_proj_res.status_code == 201
    proj_data = create_proj_res.json()
    project_id = proj_data["id"]
    assert proj_data["name"] == "Enterprise Portal"

    # 3. Start Asynchronous Scan Job
    scan_init_res = client.post(
        f"/api/v1/projects/{project_id}/scans?is_async=true",
        headers=headers
    )
    assert scan_init_res.status_code == 200
    scan_init_data = scan_init_res.json()
    job_id = scan_init_data["job_id"]
    scan_id = scan_init_data["scan_id"]
    assert scan_init_data["status"] == "QUEUED"

    # 4. Poll Async Job Queue until completion
    max_wait = 10
    start_time = time.time()
    job_completed = False

    while time.time() - start_time < max_wait:
        job_res = client.get(f"/api/v1/jobs/{job_id}", headers=headers)
        assert job_res.status_code == 200
        job_data = job_res.json()
        if job_data["status"] == "COMPLETED":
            job_completed = True
            break
        time.sleep(0.2)

    assert job_completed is True

    # 5. Verify Results Persisted in Database Table
    db = SessionLocal()
    db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
    assert db_scan is not None
    assert db_scan.status == "COMPLETED"
    assert db_scan.findings_count > 0

    db_findings = db.query(Finding).filter(Finding.project_id == project_id).all()
    assert len(db_findings) > 0
    categories = [f.category for f in db_findings]
    assert "SECRETS" in categories or "INJECTION" in categories or "CONTAINER_SECURITY" in categories
    db.close()

    # 6. Retrieve Findings via API (as Frontend does)
    get_findings_res = client.get(f"/api/v1/projects/{project_id}/findings", headers=headers)
    assert get_findings_res.status_code == 200
    findings_list = get_findings_res.json()
    assert len(findings_list) > 0

    # Pick SQLi or Secrets finding
    target_finding = [f for f in findings_list if f["category"] in ["INJECTION", "SECRETS"]][0]
    finding_id = target_finding["id"]

    # 7. Inspect Finding Details
    detail_res = client.get(f"/api/v1/findings/{finding_id}", headers=headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["title"] == target_finding["title"]

    # 8. Generate Fix Plan
    fix_plan_res = client.post(f"/api/v1/findings/{finding_id}/fix-plan", headers=headers)
    assert fix_plan_res.status_code == 200
    fix_plan = fix_plan_res.json()
    fix_id = fix_plan["id"]
    assert "diff" in fix_plan
    assert fix_plan["requires_approval"] is True

    # 9. Attempt Unapproved Fix Application -> MUST BE DENIED (HTTP 403)
    unapproved_apply_res = client.post(f"/api/v1/fixes/{fix_id}/apply", headers=headers)
    assert unapproved_apply_res.status_code == 403
    assert "human approval" in unapproved_apply_res.json()["detail"].lower()

    # 10. Grant Human Approval
    approve_res = client.post(
        f"/api/v1/fixes/{fix_id}/approve",
        json={"approved_by": "lead-sec-engineer", "decision": "APPROVED", "reason": "Verified fix diff"},
        headers=headers
    )
    assert approve_res.status_code == 200
    assert approve_res.json()["approved"] is True

    # 11. Apply Approved Patch
    apply_res = client.post(f"/api/v1/fixes/{fix_id}/apply", headers=headers)
    assert apply_res.status_code == 200
    assert apply_res.json()["status"] == "APPLIED"

    # 12. Run Verification & Independent Re-scan
    verify_res = client.post(f"/api/v1/fixes/{fix_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    ver_data = verify_res.json()
    assert ver_data["original_resolved"] is True

    # 13. Verify Database Status Updated to RESOLVED
    db = SessionLocal()
    persisted_finding = db.query(Finding).filter(Finding.id == finding_id).first()
    assert persisted_finding.status == "RESOLVED"
    db.close()

    # 14. Verify Cryptographic SHA-256 Audit Trail
    audit_res = client.get("/api/v1/audit-events", headers=headers)
    assert audit_res.status_code == 200
    audit_body = audit_res.json()
    assert audit_body["integrity_verified"] is True
    assert len(audit_body["events"]) > 0

    # 15. Cross-Tenant Denial (Tenant Isolation Test)
    # Create Foreign Organization (Competitor Corp)
    db = SessionLocal()
    foreign_org = Organization(name="Competitor Corp", slug=f"competitor-{uuid.uuid4().hex[:6]}")
    db.add(foreign_org)
    db.commit()
    db.refresh(foreign_org)
    foreign_org_id = foreign_org.id
    db.close()

    foreign_headers = {"X-Organization-Id": foreign_org_id}

    # Foreign tenant querying Acme's project MUST receive 404 (Denied)
    foreign_proj_query = client.get(f"/api/v1/projects/{project_id}", headers=foreign_headers)
    assert foreign_proj_query.status_code == 404

    # Foreign tenant querying Acme's findings MUST receive 404 (Denied)
    foreign_findings_query = client.get(f"/api/v1/projects/{project_id}/findings", headers=foreign_headers)
    assert foreign_findings_query.status_code == 404

    # Foreign tenant querying Acme's finding detail MUST receive 404 (Denied)
    foreign_finding_detail = client.get(f"/api/v1/findings/{finding_id}", headers=foreign_headers)
    assert foreign_finding_detail.status_code == 404
