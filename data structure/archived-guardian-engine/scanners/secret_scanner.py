import os
from typing import List
from .base import BaseScanner
from ..core.models import Finding, FindingSeverity, FindingEvidence
from ..core.secret_redactor import SecretRedactor

class SecretScanner(BaseScanner):
    IGNORE_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".next", "dist", "build"}

    def name(self) -> str:
        return "Guardian Secret Scanner"

    def scan(self, project_id: str, scan_id: str, workspace_root: str) -> List[Finding]:
        findings: List[Finding] = []
        abs_root = os.path.realpath(os.path.abspath(workspace_root))

        for dirpath, dirnames, filenames in os.walk(abs_root):
            dirnames[:] = [d for d in dirnames if d not in self.IGNORE_DIRS]
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_idx, line in enumerate(lines, start=1):
                    for name, pattern in SecretRedactor.PATTERNS:
                        match = pattern.search(line)
                        if match:
                            raw_val = match.group(0)
                            redacted_sample, _ = SecretRedactor.redact(line.strip())
                            fingerprint = self.generate_fingerprint("SECRET", rel_path, name, line_idx)

                            findings.append(Finding(
                                scan_id=scan_id,
                                project_id=project_id,
                                fingerprint=fingerprint,
                                category="SECRETS",
                                severity=FindingSeverity.CRITICAL,
                                confidence=0.95,
                                title=f"Exposed Secret Detected ({name})",
                                summary=f"A hardcoded credential or token ({name}) was detected in source code.",
                                affected_path=rel_path,
                                line_start=line_idx,
                                line_end=line_idx,
                                root_cause=f"Direct hardcoding of {name} in repository file.",
                                impact="Unauthorized access, cloud account takeover, data exfiltration.",
                                remediation="Revoke the exposed secret immediately, rotate credentials, and store via secure environment variables or vault.",
                                source_tool=self.name(),
                                evidence=[FindingEvidence(
                                    evidence_type="SECRET_MATCH",
                                    data=redacted_sample,
                                    file_path=rel_path,
                                    line_start=line_idx,
                                    line_end=line_idx
                                )]
                            ))

        return findings
