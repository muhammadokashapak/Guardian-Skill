import re
from typing import List, Optional, Tuple, Dict, Any
from .models import ActionClass, PolicyDecision, RiskLevel
from .path_security import PathSecurity, PathSecurityError

class PolicyEngine:
    ALLOWED_EXECUTABLES = {
        "git",
        "npm",
        "npx",
        "python",
        "pytest",
        "pip",
        "composer",
        "php",
        "node",
        "cat",
        "echo",
    }

    DISALLOWED_PATTERNS = [
        re.compile(r"[;&|`$]"),                          # Shell chaining and command substitution
        re.compile(r"(?i)\b(?:curl|wget)\b.*\|\s*(?:bash|sh|powershell|cmd)"), # Remote script piping
        re.compile(r"(?i)\b(?:rm\s+-(?:r|f|rf)|rmdir\s+/s)\b"),                 # Destructive deletion
        re.compile(r"(?i)\b(?:sudo|su|runas)\b"),                               # Privilege escalation
        re.compile(r"(?i)\b(?:mkfs|dd|format)\b"),                              # Disk destruction
        re.compile(r"(?i)\b(?:eval|exec)\b"),                                   # Dynamic execution
    ]

    NEVER_AUTOMATIC_KEYWORDS = [
        "deploy_production",
        "drop_database",
        "truncate_table",
        "export_credentials",
        "rotate_master_key",
        "disable_policy_engine",
        "weaken_guardrails",
    ]

    def __init__(self, network_enabled: bool = False, allowed_hosts: Optional[List[str]] = None):
        self.network_enabled = network_enabled
        self.allowed_hosts = allowed_hosts or ["api.openai.com", "generativelanguage.googleapis.com", "api.anthropic.com"]

    def evaluate_action(
        self,
        action_class: ActionClass,
        action_name: str,
        target_path: Optional[str] = None,
        workspace_root: Optional[str] = None,
        is_human_approved: bool = False
    ) -> Tuple[PolicyDecision, str]:
        """Evaluates whether an action is allowed, denied, or requires approval."""
        # 1. NEVER_AUTOMATIC Check
        if action_class == ActionClass.NEVER_AUTOMATIC:
            return PolicyDecision.DENY, "Execution Denied: Action is classified as NEVER_AUTOMATIC"

        for kw in self.NEVER_AUTOMATIC_KEYWORDS:
            if kw in action_name.lower():
                return PolicyDecision.DENY, f"Execution Denied: Action '{action_name}' contains restricted keyword '{kw}'"

        # 2. Path verification if path supplied
        if target_path and workspace_root:
            allow_write = action_class in [ActionClass.MODIFY, ActionClass.HIGH_RISK]
            try:
                PathSecurity.canonicalize_and_validate(workspace_root, target_path, allow_write=allow_write)
            except PathSecurityError as e:
                return PolicyDecision.DENY, str(e)

        # 3. Approval matrix
        if action_class == ActionClass.HIGH_RISK:
            if not is_human_approved:
                return PolicyDecision.REQUIRE_APPROVAL, f"High-risk action '{action_name}' requires explicit human approval"
            return PolicyDecision.ALLOW, "Approved high-risk action"

        if action_class in [ActionClass.OBSERVE, ActionClass.ANALYZE, ActionClass.TEST]:
            return PolicyDecision.ALLOW, "Low/medium risk read/analysis operation allowed"

        if action_class == ActionClass.MODIFY:
            # If modification touches critical security or auth files, escalate to HIGH_RISK
            if target_path and any(k in target_path.lower() for k in ["auth", "security", "policy", "migration", "workflow"]):
                if not is_human_approved:
                    return PolicyDecision.REQUIRE_APPROVAL, f"Modification touches critical area '{target_path}', human approval required"
            return PolicyDecision.ALLOW, "Standard modification allowed"

        # Fail closed
        return PolicyDecision.DENY, "Default deny policy triggered"

    def validate_command(self, command_parts: List[str]) -> Tuple[PolicyDecision, str]:
        """Validates command binary and arguments against strict allowlist and pattern filters."""
        if not command_parts:
            return PolicyDecision.DENY, "Empty command rejected"

        executable = command_parts[0].lower().replace(".exe", "")
        if executable not in self.ALLOWED_EXECUTABLES:
            return PolicyDecision.DENY, f"Executable '{executable}' is not in the approved binary allowlist"

        full_command_str = " ".join(command_parts)
        for pattern in self.DISALLOWED_PATTERNS:
            if pattern.search(full_command_str):
                return PolicyDecision.DENY, f"Command contains forbidden character or pattern matching '{pattern.pattern}'"

        return PolicyDecision.ALLOW, "Command passed deterministic policy checks"

    def check_network_access(self, target_host: str) -> Tuple[PolicyDecision, str]:
        if not self.network_enabled:
            return PolicyDecision.DENY, "Network access is denied by default"

        if target_host in self.allowed_hosts:
            return PolicyDecision.ALLOW, f"Host '{target_host}' is in network allowlist"

        return PolicyDecision.DENY, f"Host '{target_host}' is not in approved network allowlist"
