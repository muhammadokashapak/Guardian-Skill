import os
import json
from typing import List, Dict, Any
from .base import BaseScanner
from ..core.models import Finding, FindingSeverity, FindingEvidence

class DependencyScanner(BaseScanner):
    KNOWN_CVE_DB: Dict[str, Dict[str, Any]] = {
        "lodash": {
            "vulnerable_versions": ["4.17.15", "4.17.11", "4.17.4"],
            "cve": "CVE-2020-8203",
            "severity": FindingSeverity.HIGH,
            "title": "Prototype Pollution in lodash",
            "remediation": "Upgrade lodash to version 4.17.21 or later."
        },
        "axios": {
            "vulnerable_versions": ["0.21.1", "0.21.0"],
            "cve": "CVE-2020-28168",
            "severity": FindingSeverity.MEDIUM,
            "title": "Server-Side Request Forgery (SSRF) bypass in axios",
            "remediation": "Upgrade axios to 0.21.2 or later."
        },
        "minimist": {
            "vulnerable_versions": ["1.2.0", "0.0.8"],
            "cve": "CVE-2020-7598",
            "severity": FindingSeverity.HIGH,
            "title": "Prototype Pollution in minimist",
            "remediation": "Upgrade minimist to 1.2.6 or later."
        },
        "fastapi": {
            "vulnerable_versions": ["0.65.0"],
            "cve": "CVE-2021-32677",
            "severity": FindingSeverity.MEDIUM,
            "title": "FastAPI content-type validation bypass",
            "remediation": "Upgrade fastapi to 0.65.2 or later."
        }
    }

    def name(self) -> str:
        return "Guardian Software Supply Chain & Dependency Scanner"

    def scan(self, project_id: str, scan_id: str, workspace_root: str) -> List[Finding]:
        findings: List[Finding] = []
        abs_root = os.path.realpath(os.path.abspath(workspace_root))

        # 1. Check package.json
        pkg_json = os.path.join(abs_root, "package.json")
        if os.path.exists(pkg_json):
            try:
                with open(pkg_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    for pkg, ver in deps.items():
                        clean_ver = ver.replace("^", "").replace("~", "").replace("v", "")
                        if pkg in self.KNOWN_CVE_DB:
                            info = self.KNOWN_CVE_DB[pkg]
                            if clean_ver in info["vulnerable_versions"]:
                                fp = self.generate_fingerprint("DEPENDENCY", "package.json", info["cve"])
                                findings.append(Finding(
                                    scan_id=scan_id,
                                    project_id=project_id,
                                    fingerprint=fp,
                                    category="SUPPLY_CHAIN",
                                    severity=info["severity"],
                                    confidence=0.98,
                                    title=f"{info['title']} ({info['cve']})",
                                    summary=f"Dependency '{pkg}' version '{ver}' has known vulnerability {info['cve']}.",
                                    affected_path="package.json",
                                    root_cause=f"Pinning vulnerable dependency {pkg}@{ver}",
                                    impact="Security bypass, denial of service, or remote code execution via vulnerable package.",
                                    remediation=info["remediation"],
                                    source_tool=self.name(),
                                    evidence=[FindingEvidence(
                                        evidence_type="PACKAGE_MANIFEST_MATCH",
                                        data=f"{pkg}: {ver} (CVE: {info['cve']})",
                                        file_path="package.json"
                                    )]
                                ))
            except Exception:
                pass

        return findings
