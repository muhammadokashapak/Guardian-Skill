from typing import List, Dict
import uuid
from .base import BaseScanner
from .sast_scanner import SASTScanner
from .secret_scanner import SecretScanner
from .dependency_scanner import DependencyScanner
from .docker_ci_scanner import DockerAndCIScanner
from .prompt_injection_scanner import PromptInjectionScanner
from ..core.models import Finding
from ..core.audit_logger import AuditLogger, ActionClass, PolicyDecision, RiskLevel

class ScanManager:
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.scanners: List[BaseScanner] = [
            SecretScanner(),
            SASTScanner(),
            DependencyScanner(),
            DockerAndCIScanner(),
            PromptInjectionScanner()
        ]

    def run_full_scan(self, project_id: str, workspace_root: str) -> List[Finding]:
        scan_id = str(uuid.uuid4())
        self.audit_logger.record_event(
            event_type="SCAN_STARTED",
            target_type="PROJECT",
            target_id=project_id,
            action_class=ActionClass.ANALYZE,
            policy_decision=PolicyDecision.ALLOW,
            project_id=project_id,
            metadata={"scan_id": scan_id, "scanners": [s.name() for s in self.scanners]}
        )

        all_findings: Dict[str, Finding] = {}

        for scanner in self.scanners:
            try:
                results = scanner.scan(project_id, scan_id, workspace_root)
                for finding in results:
                    # Deduplicate by fingerprint
                    if finding.fingerprint not in all_findings:
                        all_findings[finding.fingerprint] = finding
            except Exception as e:
                self.audit_logger.record_event(
                    event_type="SCANNER_ERROR",
                    target_type="SCANNER",
                    target_id=scanner.name(),
                    action_class=ActionClass.ANALYZE,
                    policy_decision=PolicyDecision.ALLOW,
                    project_id=project_id,
                    metadata={"error": str(e)}
                )

        findings_list = list(all_findings.values())
        self.audit_logger.record_event(
            event_type="SCAN_COMPLETED",
            target_type="PROJECT",
            target_id=project_id,
            action_class=ActionClass.ANALYZE,
            policy_decision=PolicyDecision.ALLOW,
            project_id=project_id,
            metadata={"scan_id": scan_id, "findings_count": len(findings_list)}
        )

        return findings_list

__all__ = [
    "BaseScanner",
    "SASTScanner",
    "SecretScanner",
    "DependencyScanner",
    "DockerAndCIScanner",
    "PromptInjectionScanner",
    "ScanManager"
]
