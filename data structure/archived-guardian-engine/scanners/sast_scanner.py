import os
import re
from typing import List, Dict, Any
from .base import BaseScanner
from ..core.models import Finding, FindingSeverity, FindingEvidence

class SASTRule:
    def __init__(self, rule_id: str, title: str, category: str, severity: FindingSeverity, pattern: re.Pattern, explanation: str, remediation: str, exts: List[str]):
        self.rule_id = rule_id
        self.title = title
        self.category = category
        self.severity = severity
        self.pattern = pattern
        self.explanation = explanation
        self.remediation = remediation
        self.exts = exts

class SASTScanner(BaseScanner):
    IGNORE_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".next", "dist", "build"}

    def __init__(self):
        self.rules: List[SASTRule] = [
            SASTRule(
                rule_id="SQLI_RAW_CONCAT",
                title="Potential SQL Injection via Raw Query Concatenation / Interpolation",
                category="INJECTION",
                severity=FindingSeverity.HIGH,
                pattern=re.compile(r"(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+.*(?:\$\{.*?\}|['\"]\s*\+\s*|\.\s*\$[a-zA-Z0-9_]+|\bDB::select\s*\(\s*['\"].*\.)"),
                explanation="SQL query appears to interpolate or concatenate unescaped user-controlled input directly into the query string.",
                remediation="Use parameterized queries or ORM query builder binding (e.g., PDO parameter placeholders or query parameters).",
                exts=[".php", ".js", ".ts", ".py"]
            ),
            SASTRule(
                rule_id="COMMAND_INJECTION",
                title="Command Injection via Untrusted Shell Execution",
                category="INJECTION",
                severity=FindingSeverity.CRITICAL,
                pattern=re.compile(r"(?:os\.system\s*\(|subprocess\.(?:run|Popen|call)\s*\(.*shell\s*=\s*True|exec\s*\(|system\s*\()"),
                explanation="Execution of shell commands with potential untrusted input or shell=True flag enables arbitrary OS command execution.",
                remediation="Pass command arguments as an array/list, avoid shell=True, and validate input against a strict allowlist.",
                exts=[".py", ".php", ".js"]
            ),
            SASTRule(
                rule_id="REFLECTED_XSS",
                title="Cross-Site Scripting (XSS) via Unsanitized Output",
                category="XSS",
                severity=FindingSeverity.HIGH,
                pattern=re.compile(r"(?:res\.send\s*\(.*<.*>|dangerouslySetInnerHTML|echo\s+\$_GET|\.innerHTML\s*=)"),
                explanation="User input is rendered directly into HTML response without context-aware escaping.",
                remediation="Sanitize and escape user input before rendering, or use template engines with automatic HTML encoding.",
                exts=[".js", ".jsx", ".ts", ".tsx", ".php"]
            ),
            SASTRule(
                rule_id="UNSAFE_DESERIALIZATION",
                title="Insecure Deserialization",
                category="DESERIALIZATION",
                severity=FindingSeverity.CRITICAL,
                pattern=re.compile(r"(?:pickle\.loads\s*\(|unserialize\s*\()"),
                explanation="Deserializing untrusted data can result in remote code execution (RCE).",
                remediation="Use safe serialization formats like JSON, or verify signatures before deserialization.",
                exts=[".py", ".php"]
            ),
            SASTRule(
                rule_id="PATH_TRAVERSAL",
                title="Path Traversal in File Access",
                category="FILE_SECURITY",
                severity=FindingSeverity.HIGH,
                pattern=re.compile(r"(?:open\s*\(\s*f?['\"].*\{[a-zA-Z0-9_]+\}|fs\.readFile(?:Sync)?\s*\(.*req\.(?:query|params)|(?:open|readFile)\s*\(.*filename)"),
                explanation="File path is constructed dynamically using request parameters without path canonicalization.",
                remediation="Use basename/realpath validation and ensure paths are strictly contained within the intended root directory.",
                exts=[".py", ".js", ".ts"]
            ),
            SASTRule(
                rule_id="MASS_ASSIGNMENT",
                title="Unprotected Mass Assignment in Model Update",
                category="AUTHORIZATION",
                severity=FindingSeverity.MEDIUM,
                pattern=re.compile(r"(?:->update\s*\(\s*\$request->all\(\)\s*\)|\.update\s*\(\s*req\.body\s*\))"),
                explanation="Updating database models directly with entire request payload can allow attackers to overwrite protected fields.",
                remediation="Explicitly specify fillable/guarded attributes, or use validated request data ($request->validated()).",
                exts=[".php", ".js", ".ts"]
            )
        ]

    def name(self) -> str:
        return "Guardian Static Application Security Testing (SAST)"

    def scan(self, project_id: str, scan_id: str, workspace_root: str) -> List[Finding]:
        findings: List[Finding] = []
        abs_root = os.path.realpath(os.path.abspath(workspace_root))

        for dirpath, dirnames, filenames in os.walk(abs_root):
            dirnames[:] = [d for d in dirnames if d not in self.IGNORE_DIRS]
            for filename in filenames:
                ext = os.path.splitext(filename)[1].lower()
                applicable_rules = [r for r in self.rules if ext in r.exts]
                if not applicable_rules:
                    continue

                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")

                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_idx, line in enumerate(lines, start=1):
                    for rule in applicable_rules:
                        if rule.pattern.search(line):
                            fingerprint = self.generate_fingerprint(rule.category, rel_path, rule.rule_id, line_idx)
                            findings.append(Finding(
                                scan_id=scan_id,
                                project_id=project_id,
                                fingerprint=fingerprint,
                                category=rule.category,
                                severity=rule.severity,
                                confidence=0.85,
                                title=rule.title,
                                summary=rule.explanation,
                                affected_path=rel_path,
                                line_start=line_idx,
                                line_end=line_idx,
                                root_cause=f"Matched SAST rule {rule.rule_id}",
                                impact="Code execution, data exposure, or unauthorized modification.",
                                remediation=rule.remediation,
                                source_tool=self.name(),
                                evidence=[FindingEvidence(
                                    evidence_type="CODE_SNIPPET",
                                    data=line.strip()[:200],
                                    file_path=rel_path,
                                    line_start=line_idx,
                                    line_end=line_idx
                                )]
                            ))

        return findings
