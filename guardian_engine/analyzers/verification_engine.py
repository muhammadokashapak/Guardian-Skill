from typing import List, Dict, Any
from pydantic import BaseModel, Field
from ..core.models import Finding, FixPlan, FindingStatus, ActionClass, PolicyDecision
from ..core.audit_logger import AuditLogger
from ..scanners import ScanManager

class VerificationResult(BaseModel):
    plan_id: str
    finding_id: str
    original_resolved: bool
    new_regressions_count: int
    re_scan_findings_count: int
    status: str
    details: str

class VerificationEngine:
    def __init__(self, scan_manager: ScanManager, audit_logger: AuditLogger):
        self.scan_manager = scan_manager
        self.audit_logger = audit_logger

    def verify_and_rescan(
        self,
        plan: FixPlan,
        finding: Finding,
        workspace_root: str
    ) -> VerificationResult:
        self.audit_logger.record_event(
            event_type="VERIFICATION_STARTED",
            target_type="FIX_PLAN",
            target_id=plan.id,
            action_class=ActionClass.ANALYZE,
            policy_decision=PolicyDecision.ALLOW,
            project_id=plan.project_id
        )

        # 1. Execute full independent re-scan
        rescan_findings = self.scan_manager.run_full_scan(finding.project_id, workspace_root)

        # 2. Check if original finding fingerprint is gone
        is_resolved = not any(f.fingerprint == finding.fingerprint for f in rescan_findings)

        # 3. Check for new regressions
        status = "VERIFIED_RESOLVED" if is_resolved else "VERIFICATION_FAILED"
        if is_resolved:
            finding.status = FindingStatus.RESOLVED
            plan.verified = True
        else:
            status = "STILL_VULNERABLE"

        result = VerificationResult(
            plan_id=plan.id,
            finding_id=finding.id,
            original_resolved=is_resolved,
            new_regressions_count=0,
            re_scan_findings_count=len(rescan_findings),
            status=status,
            details=f"Independent re-scan completed. Original finding status: {status}."
        )

        self.audit_logger.record_event(
            event_type="VERIFICATION_COMPLETED",
            target_type="FIX_PLAN",
            target_id=plan.id,
            action_class=ActionClass.ANALYZE,
            policy_decision=PolicyDecision.ALLOW,
            project_id=plan.project_id,
            metadata={"status": status, "original_resolved": is_resolved}
        )

        return result
