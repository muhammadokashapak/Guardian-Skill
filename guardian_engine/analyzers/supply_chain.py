import os
import json
import re
from typing import List, Dict, Any
from pydantic import BaseModel, Field

class SupplyChainRisk(BaseModel):
    package_name: str
    manifest_file: str
    risk_type: str  # SUSPICIOUS_SCRIPT, UNPINNED_VERSION, CVE, TYPOSQUAT_RISK
    severity: str
    details: str
    remediation: str

class SupplyChainAuditReport(BaseModel):
    project_root: str
    total_dependencies: int
    unpinned_count: int
    risky_scripts_count: int
    risks: List[SupplyChainRisk] = Field(default_factory=list)
    overall_health: str

class SupplyChainGuardian:
    SUSPICIOUS_SCRIPT_PATTERNS = [
        re.compile(r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|node)"),
        re.compile(r"\b(?:nc|netcat|ncat)\b"),
        re.compile(r"\b(?:base64\s+-d|atob)\b"),
    ]

    def audit(self, workspace_root: str) -> SupplyChainAuditReport:
        abs_root = os.path.realpath(os.path.abspath(workspace_root))
        risks: List[SupplyChainRisk] = []
        total_deps = 0
        unpinned = 0
        risky_scripts = 0

        # 1. Audit package.json
        pkg_path = os.path.join(abs_root, "package.json")
        if os.path.exists(pkg_path):
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg_data = json.load(f)

                # Scripts audit
                scripts = pkg_data.get("scripts", {})
                for s_name, s_cmd in scripts.items():
                    if s_name in ["preinstall", "install", "postinstall"]:
                        for pat in self.SUSPICIOUS_SCRIPT_PATTERNS:
                            if pat.search(s_cmd):
                                risky_scripts += 1
                                risks.append(SupplyChainRisk(
                                    package_name=pkg_data.get("name", "root-project"),
                                    manifest_file="package.json",
                                    risk_type="SUSPICIOUS_LIFECYCLE_SCRIPT",
                                    severity="CRITICAL",
                                    details=f"Package lifecycle script '{s_name}' executes suspicious command: {s_cmd}",
                                    remediation="Remove arbitrary remote script execution from install hooks."
                                ))

                # Dependencies audit
                deps = {**pkg_data.get("dependencies", {}), **pkg_data.get("devDependencies", {})}
                total_deps += len(deps)
                for dep_name, dep_ver in deps.items():
                    if dep_ver.startswith("*") or dep_ver.startswith(">=") or dep_ver == "latest":
                        unpinned += 1
                        risks.append(SupplyChainRisk(
                            package_name=dep_name,
                            manifest_file="package.json",
                            risk_type="UNPINNED_VERSION",
                            severity="LOW",
                            details=f"Dependency '{dep_name}' version '{dep_ver}' is unpinned.",
                            remediation="Pin exact or caret-bounded semantic version to prevent unexpected upstream breaks."
                        ))
            except Exception:
                pass

        health = "CRITICAL" if any(r.severity == "CRITICAL" for r in risks) else ("WARNING" if risks else "HEALTHY")

        return SupplyChainAuditReport(
            project_root=abs_root,
            total_dependencies=total_deps,
            unpinned_count=unpinned,
            risky_scripts_count=risky_scripts,
            risks=risks,
            overall_health=health
        )
