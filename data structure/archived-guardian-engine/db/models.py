import uuid
import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, JSON, Index
)
from sqlalchemy.orm import relationship
from .database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

# 1. Organizations
class Organization(Base):
    __tablename__ = "organizations"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    users = relationship("User", back_populates="organization", cascade="all, delete-orphan")
    projects = relationship("Project", back_populates="organization", cascade="all, delete-orphan")

# 2. Users
class User(Base):
    __tablename__ = "users"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    role = Column(String(50), default="DEVELOPER")  # ADMIN, SECURITY_ENGINEER, DEVELOPER, QA_ENGINEER, AUDITOR
    api_key = Column(String(64), unique=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="users")

# 3. Projects
class Project(Base):
    __tablename__ = "projects"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    root_path = Column(String(1024), nullable=False)
    repository_type = Column(String(50), default="git")
    default_branch = Column(String(100), default="main")
    risk_profile = Column(String(50), default="MEDIUM")
    status = Column(String(50), default="ACTIVE")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    organization = relationship("Organization", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="project", cascade="all, delete-orphan")
    fixes = relationship("Fix", back_populates="project", cascade="all, delete-orphan")
    snapshots = relationship("ProjectSnapshot", back_populates="project", cascade="all, delete-orphan")
    dependencies = relationship("Dependency", back_populates="project", cascade="all, delete-orphan")
    incidents = relationship("Incident", back_populates="project", cascade="all, delete-orphan")
    change_requests = relationship("ChangeRequest", back_populates="project", cascade="all, delete-orphan")
    test_plans = relationship("TestPlan", back_populates="project", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_project_org_status", "organization_id", "status"),
    )

# 4. Project Repositories
class ProjectRepository(Base):
    __tablename__ = "project_repositories"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    remote_url = Column(String(1024), nullable=False)
    provider = Column(String(50), default="github")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 5. Project Snapshots
class ProjectSnapshot(Base):
    __tablename__ = "project_snapshots"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    commit_hash = Column(String(64), default="HEAD")
    tree_hash = Column(String(64), nullable=False, index=True)
    file_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="snapshots")

# 6. Scans
class Scan(Base):
    __tablename__ = "scans"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    snapshot_id = Column(String(36), nullable=True)
    scan_type = Column(String(50), default="FULL")
    status = Column(String(50), default="QUEUED", index=True)  # QUEUED, RUNNING, COMPLETED, FAILED, PARTIAL
    engine_version = Column(String(50), default="1.0.0")
    findings_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

# 7. Findings
class Finding(Base):
    __tablename__ = "findings"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    category = Column(String(100), nullable=False, index=True)
    severity = Column(String(50), nullable=False, index=True)  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, default=1.0)
    status = Column(String(50), default="OPEN", index=True)    # OPEN, FIX_PLANNED, IN_REVIEW, APPROVED, APPLIED, VERIFIED, RESOLVED
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    affected_path = Column(String(1024), nullable=False)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    root_cause = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    source_tool = Column(String(100), default="guardian-scanner")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    project = relationship("Project", back_populates="findings")
    evidence = relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    fixes = relationship("Fix", back_populates="finding", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_finding_proj_fingerprint", "project_id", "fingerprint"),
        Index("ix_finding_proj_status", "project_id", "status"),
    )

# 8. Finding Evidence
class FindingEvidence(Base):
    __tablename__ = "finding_evidence"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(100), nullable=False)
    data = Column(Text, nullable=False)
    file_path = Column(String(1024), nullable=True)
    line_start = Column(Integer, nullable=True)
    line_end = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    finding = relationship("Finding", back_populates="evidence")

# 9. Dependencies
class Dependency(Base):
    __tablename__ = "dependencies"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    version = Column(String(100), nullable=False)
    package_manager = Column(String(50), nullable=False)
    is_direct = Column(Boolean, default=True)
    has_vulnerability = Column(Boolean, default=False)
    cve_id = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="dependencies")

# 10. Incidents
class Incident(Base):
    __tablename__ = "incidents"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    status = Column(String(50), default="INVESTIGATING")
    probable_root_cause = Column(Text, nullable=True)
    confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="incidents")
    evidence = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")

# 11. Incident Evidence
class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    data = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    incident = relationship("Incident", back_populates="evidence")

# 12. Change Requests
class ChangeRequest(Base):
    __tablename__ = "change_requests"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    description = Column(Text, nullable=False)
    target_file = Column(String(1024), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="change_requests")
    impacts = relationship("ChangeImpact", back_populates="change_request", cascade="all, delete-orphan")

# 13. Change Impacts
class ChangeImpact(Base):
    __tablename__ = "change_impacts"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    change_request_id = Column(String(36), ForeignKey("change_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    affected_files = Column(JSON, nullable=False)
    affected_apis = Column(JSON, nullable=False)
    migration_required = Column(Boolean, default=False)
    backward_compatible = Column(Boolean, default=True)
    deployment_risk = Column(String(50), default="LOW")
    ai_reasoning = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    change_request = relationship("ChangeRequest", back_populates="impacts")

# 14. Test Plans
class TestPlan(Base):
    __tablename__ = "test_plans"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    feature_name = Column(String(255), nullable=False)
    risk_assessment = Column(String(50), default="MEDIUM")
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    project = relationship("Project", back_populates="test_plans")
    test_cases = relationship("TestCase", back_populates="test_plan", cascade="all, delete-orphan")
    runs = relationship("TestRun", back_populates="test_plan", cascade="all, delete-orphan")

# 15. Test Cases
class TestCase(Base):
    __tablename__ = "test_cases"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    test_plan_id = Column(String(36), ForeignKey("test_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    category = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    command = Column(JSON, nullable=False)
    expected_outcome = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    test_plan = relationship("TestPlan", back_populates="test_cases")

# 16. Test Runs
class TestRun(Base):
    __tablename__ = "test_runs"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    test_plan_id = Column(String(36), ForeignKey("test_plans.id", ondelete="CASCADE"), nullable=False, index=True)
    total_tests = Column(Integer, default=0)
    passed_tests = Column(Integer, default=0)
    failed_tests = Column(Integer, default=0)
    verdict = Column(String(50), default="PASS")
    logs = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    test_plan = relationship("TestPlan", back_populates="runs")

# 17. Fixes
class Fix(Base):
    __tablename__ = "fixes"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    explanation = Column(Text, nullable=False)
    diff = Column(Text, nullable=False)
    target_files = Column(JSON, nullable=False)
    risk_level = Column(String(50), default="HIGH")
    requires_approval = Column(Boolean, default=True)
    approved = Column(Boolean, default=False)
    applied = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    finding = relationship("Finding", back_populates="fixes")
    project = relationship("Project", back_populates="fixes")
    approvals = relationship("Approval", back_populates="fix", cascade="all, delete-orphan")
    verification_runs = relationship("VerificationRun", back_populates="fix", cascade="all, delete-orphan")

# 18. Approvals
class Approval(Base):
    __tablename__ = "approvals"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    fix_id = Column(String(36), ForeignKey("fixes.id", ondelete="CASCADE"), nullable=False, index=True)
    requested_by = Column(String(255), nullable=False)
    approved_by = Column(String(255), nullable=True)
    risk_level = Column(String(50), nullable=False)
    decision = Column(String(50), default="PENDING")  # PENDING, APPROVED, REJECTED
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    fix = relationship("Fix", back_populates="approvals")

# 19. Verification Runs
class VerificationRun(Base):
    __tablename__ = "verification_runs"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    fix_id = Column(String(36), ForeignKey("fixes.id", ondelete="CASCADE"), nullable=False, index=True)
    original_resolved = Column(Boolean, default=False)
    new_regressions_count = Column(Integer, default=0)
    status = Column(String(50), default="VERIFIED_RESOLVED")
    details = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    fix = relationship("Fix", back_populates="verification_runs")

# 20. Guardian Policies
class Policy(Base):
    __tablename__ = "policies"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    action_class = Column(String(50), nullable=False)
    rules_json = Column(JSON, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 21. Tool Executions
class ToolExecution(Base):
    __tablename__ = "tool_executions"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), nullable=False, index=True)
    tool_name = Column(String(100), nullable=False)
    command = Column(JSON, nullable=False)
    policy_decision = Column(String(50), nullable=False)
    exit_code = Column(Integer, nullable=False)
    duration_sec = Column(Float, default=0.0)
    redacted_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 22. Audit Events
class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), nullable=False, index=True)
    project_id = Column(String(36), nullable=True, index=True)
    actor_type = Column(String(50), default="SYSTEM")
    actor_id = Column(String(255), default="guardian-daemon")
    event_type = Column(String(100), nullable=False, index=True)
    target_type = Column(String(100), nullable=False)
    target_id = Column(String(255), nullable=False)
    action_class = Column(String(50), default="OBSERVE")
    policy_decision = Column(String(50), default="ALLOW")
    risk_level = Column(String(50), default="LOW")
    metadata_json = Column(JSON, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    hash = Column(String(64), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 23. Reports
class Report(Base):
    __tablename__ = "reports"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), nullable=False, index=True)
    report_type = Column(String(50), default="EXECUTIVE")  # EXECUTIVE, TECHNICAL, COMPLIANCE
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

# 24. AI Runs
class AiRun(Base):
    __tablename__ = "ai_runs"
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), nullable=True, index=True)
    provider = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
