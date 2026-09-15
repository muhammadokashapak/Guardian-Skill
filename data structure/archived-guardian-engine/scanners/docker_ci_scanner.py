import os
import re
from typing import List
from .base import BaseScanner
from ..core.models import Finding, FindingSeverity, FindingEvidence

class DockerAndCIScanner(BaseScanner):
    def name(self) -> str:
        return "Guardian Container & CI/CD Security Scanner"

    def scan(self, project_id: str, scan_id: str, workspace_root: str) -> List[Finding]:
        findings: List[Finding] = []
        abs_root = os.path.realpath(os.path.abspath(workspace_root))

        for dirpath, _, filenames in os.walk(abs_root):
            for filename in filenames:
                full_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(full_path, abs_root).replace("\\", "/")
                fl = filename.lower()

                # Dockerfile audits
                if "dockerfile" in fl:
                    self._audit_dockerfile(full_path, rel_path, project_id, scan_id, findings)

                # CI/CD workflows
                if ".github/workflows" in rel_path or fl == ".gitlab-ci.yml":
                    self._audit_ci_workflow(full_path, rel_path, project_id, scan_id, findings)

        return findings

    def _audit_dockerfile(self, full_path: str, rel_path: str, project_id: str, scan_id: str, findings: List[Finding]):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return

        for idx, line in enumerate(lines, start=1):
            # Check root user
            if re.search(r"^\s*USER\s+root\b", line):
                fp = self.generate_fingerprint("CONTAINER_SECURITY", rel_path, "DOCKER_ROOT_USER", idx)
                findings.append(Finding(
                    scan_id=scan_id,
                    project_id=project_id,
                    fingerprint=fp,
                    category="CONTAINER_SECURITY",
                    severity=FindingSeverity.HIGH,
                    confidence=0.9,
                    title="Container Configured to Run as Root",
                    summary="Dockerfile explicitly sets execution user to root, increasing container breakout risk.",
                    affected_path=rel_path,
                    line_start=idx,
                    line_end=idx,
                    root_cause="Explicit USER root directive",
                    impact="If the container application is compromised, the attacker has host-equivalent root permissions.",
                    remediation="Create a dedicated non-root application user and group (e.g., USER node or USER appuser).",
                    source_tool=self.name(),
                    evidence=[FindingEvidence(evidence_type="DOCKERFILE_DIRECTIVE", data=line.strip(), file_path=rel_path, line_start=idx, line_end=idx)]
                ))

            # Check curl | bash
            if re.search(r"(?:curl|wget)\b.*\|\s*(?:bash|sh)", line):
                fp = self.generate_fingerprint("CONTAINER_SECURITY", rel_path, "DOCKER_CURL_PIPE", idx)
                findings.append(Finding(
                    scan_id=scan_id,
                    project_id=project_id,
                    fingerprint=fp,
                    category="CONTAINER_SECURITY",
                    severity=FindingSeverity.HIGH,
                    confidence=0.95,
                    title="Insecure Script Piping via Remote Download (curl | bash)",
                    summary="Dockerfile pipes arbitrary remote scripts directly into bash without integrity verification.",
                    affected_path=rel_path,
                    line_start=idx,
                    line_end=idx,
                    root_cause="Piping remote script to shell in RUN directive",
                    impact="MITM or compromised remote server can inject arbitrary commands into build image.",
                    remediation="Download script, verify SHA256 checksum, and inspect before execution.",
                    source_tool=self.name(),
                    evidence=[FindingEvidence(evidence_type="DOCKERFILE_DIRECTIVE", data=line.strip(), file_path=rel_path, line_start=idx, line_end=idx)]
                ))

    def _audit_ci_workflow(self, full_path: str, rel_path: str, project_id: str, scan_id: str, findings: List[Finding]):
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return

        # Check pull_request_target
        if "pull_request_target:" in content and "head.sha" in content:
            fp = self.generate_fingerprint("CI_CD_SECURITY", rel_path, "PR_TARGET_POISONING")
            findings.append(Finding(
                scan_id=scan_id,
                project_id=project_id,
                fingerprint=fp,
                category="CI_CD_SECURITY",
                severity=FindingSeverity.CRITICAL,
                confidence=0.95,
                title="Dangerous pull_request_target Checkout in CI Workflow",
                summary="Workflow triggers on pull_request_target and checks out untrusted PR head commit, allowing repository secret exfiltration.",
                affected_path=rel_path,
                root_cause="pull_request_target combined with explicit checkout of untrusted PR SHA",
                impact="Untrusted pull requests can run malicious code in the context of the base repository with full access to repository secrets.",
                remediation="Use standard 'pull_request' trigger, or never checkout PR head SHA when running with elevated permissions.",
                source_tool=self.name(),
                evidence=[FindingEvidence(evidence_type="CI_WORKFLOW_TRIGGER", data="pull_request_target with head.sha checkout", file_path=rel_path)]
            ))

        # Check write-all permissions
        if re.search(r"permissions:\s*write-all", content):
            fp = self.generate_fingerprint("CI_CD_SECURITY", rel_path, "EXCESSIVE_CI_PERMISSIONS")
            findings.append(Finding(
                scan_id=scan_id,
                project_id=project_id,
                fingerprint=fp,
                category="CI_CD_SECURITY",
                severity=FindingSeverity.HIGH,
                confidence=0.95,
                title="Excessive CI/CD Token Permissions (write-all)",
                summary="Workflow requests unrestricted write-all permissions for GITHUB_TOKEN.",
                affected_path=rel_path,
                root_cause="Explicit permissions: write-all declaration",
                impact="Violates principle of least privilege, enabling any compromised step to modify releases, contents, or issues.",
                remediation="Scope permissions to minimal required scopes (e.g., contents: read).",
                source_tool=self.name(),
                evidence=[FindingEvidence(evidence_type="CI_PERMISSIONS_MATCH", data="permissions: write-all", file_path=rel_path)]
            ))
