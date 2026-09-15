from __future__ import annotations
import uuid
import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

class ActionClass(str, Enum):
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    TEST = "TEST"
    MODIFY = "MODIFY"
    HIGH_RISK = "HIGH_RISK"
    NEVER_AUTOMATIC = "NEVER_AUTOMATIC"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FindingStatus(str, Enum):
    OPEN = "OPEN"
    FIX_PLANNED = "FIX_PLANNED"
    IN_REVIEW = "IN_REVIEW"
    APPROVED = "APPROVED"
    APPLIED = "APPLIED"
    VERIFIED = "VERIFIED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"

class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"

class Project(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = "org-default"
    name: str
    root_path: str
    repository_type: str = "git"
    default_branch: str = "main"
    risk_profile: RiskLevel = RiskLevel.MEDIUM
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

class Snapshot(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    project_id: str
    commit_hash: Optional[str] = "HEAD"
    tree_hash: str
    file_count: int
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

class FindingEvidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: str
    data: str
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None

class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scan_id: str
    project_id: str
    fingerprint: str
    category: str
    severity: FindingSeverity
    confidence: float = 1.0
    status: FindingStatus = FindingStatus.OPEN
    title: str
    summary: str
    affected_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    root_cause: str = ""
    impact: str = ""
    remediation: str = ""
    source_tool: str = "guardian-scanner"
    evidence: List[FindingEvidence] = Field(default_factory=list)
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

class FixPlan(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    project_id: str
    title: str
    explanation: str
    diff: str
    target_files: List[str]
    risk_level: RiskLevel
    requires_approval: bool = True
    approved: bool = False
    applied: bool = False
    verified: bool = False
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization_id: str = "org-default"
    project_id: Optional[str] = None
    actor_type: str = "SYSTEM"
    actor_id: str = "guardian-daemon"
    event_type: str
    target_type: str
    target_id: str
    action_class: ActionClass = ActionClass.OBSERVE
    policy_decision: PolicyDecision = PolicyDecision.ALLOW
    risk_level: RiskLevel = RiskLevel.LOW
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
