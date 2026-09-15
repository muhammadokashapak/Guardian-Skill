import os
import re
from typing import List
from .base import BaseScanner
from ..core.models import Finding, FindingSeverity, FindingEvidence

class PromptInjectionScanner(BaseScanner):
    INJECTION_PATTERNS = [
        ("INSTRUCTION_OVERRIDE", re.compile(r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b")),
        ("SYSTEM_PROMPT_SPOOF", re.compile(r"(?i)\b(?:SYSTEM\s+DIRECTIVE|SYSTEM\s+INSTRUCTION|NEW\s+INSTRUCTION|DEVELOPER\s+MODE)\b")),
        ("CREDENTIAL_EXFIL_ATTEMPT", re.compile(r"(?i)\b(?:print|exfiltrate|send|leak|dump)\s+(?:all\s+)?(?:secrets?|passwords?|env(?:ironment)?\s+vars?|tokens?|keys?)\b")),
        ("POLICY_BYPASS_ATTEMPT", re.compile(r"(?i)\b(?:disable|bypass|weaken)\s+(?:security\s+)?(?:policies|sandbox|guardrails)\b")),
    ]

    def name(self) -> str:
        return "Guardian Untrusted Repository Instruction & Prompt Injection Scanner"

    def scan(self, project_id: str, scan_id: str, workspace_root: str) -> List[Finding]:
        findings: List[Finding] = []
        abs_root = os.path.realpath(os.path.abspath(workspace_root))

        for dirpath, _, filenames in os.walk(abs_root):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for idx, line in enumerate(lines, start=1):
                    for rule_id, pattern in self.INJECTION_PATTERNS:
                        if pattern.search(line):
                            fp = self.generate_fingerprint("PROMPT_INJECTION", rel_path, rule_id, idx)
                            findings.append(Finding(
                                scan_id=scan_id,
                                project_id=project_id,
                                fingerprint=fp,
                                category="PROMPT_INJECTION",
                                severity=FindingSeverity.HIGH,
                                confidence=0.9,
                                title=f"Potential Prompt Injection Pattern in Repository File ({rule_id})",
                                summary="Repository content contains directives attempting to override AI instructions or extract secrets.",
                                affected_path=rel_path,
                                line_start=idx,
                                line_end=idx,
                                root_cause=f"Matched prompt injection heuristic {rule_id}",
                                impact="Untrusted repository files could manipulate non-hardened AI agent workflows.",
                                remediation="Treat all repository content as untrusted data. Ensure AI reasoning pipelines wrap content in strict data boundaries and ignore embedded directives.",
                                source_tool=self.name(),
                                evidence=[FindingEvidence(
                                    evidence_type="INJECTION_MATCH",
                                    data=line.strip()[:150],
                                    file_path=rel_path,
                                    line_start=idx,
                                    line_end=idx
                                )]
                            ))

        return findings

    def scan_content(self, text: str, affected_path: str = "buffer") -> List[Finding]:
        findings: List[Finding] = []
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            for rule_id, pattern in self.INJECTION_PATTERNS:
                if pattern.search(line):
                    fp = self.generate_fingerprint("PROMPT_INJECTION", affected_path, rule_id, idx)
                    findings.append(Finding(
                        scan_id="scan-mem",
                        project_id="proj-mem",
                        fingerprint=fp,
                        category="PROMPT_INJECTION",
                        severity=FindingSeverity.HIGH,
                        confidence=0.9,
                        title=f"Potential Prompt Injection Pattern in Repository File ({rule_id})",
                        summary="Repository content contains directives attempting to override AI instructions or extract secrets.",
                        affected_path=affected_path,
                        line_start=idx,
                        line_end=idx,
                        root_cause=f"Matched prompt injection heuristic {rule_id}",
                        impact="Untrusted repository files could manipulate non-hardened AI agent workflows.",
                        remediation="Treat all repository content as untrusted data. Ensure AI reasoning pipelines wrap content in strict data boundaries and ignore embedded directives.",
                        source_tool=self.name(),
                        evidence=[FindingEvidence(
                            evidence_type="INJECTION_MATCH",
                            data=line.strip()[:150],
                            file_path=affected_path,
                            line_start=idx,
                            line_end=idx
                        )]
                    ))
        return findings
