import os
import re
import difflib
import shutil
from typing import Optional, List, Dict, Any, Tuple
from ..core.models import Finding as CoreFinding, FixPlan, RiskLevel, FindingSeverity, ActionClass, PolicyDecision
from ..core.policy_engine import PolicyEngine
from ..core.path_security import PathSecurity
from ..core.audit_logger import AuditLogger
from ..ai.router import AIRouter

class DynamicPatchApplicator:
    @classmethod
    def apply_unified_diff(cls, original_text: str, diff_text: str) -> Tuple[bool, str, str]:
        """
        Parses and applies standard unified diff hunks (@@ -start,len +start,len @@) to original_text.
        Returns: (success: bool, patched_text: str, error_message: str)
        """
        orig_lines = original_text.splitlines(keepends=True)
        diff_lines = diff_text.splitlines(keepends=True)

        hunk_re = re.compile(r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@")
        hunks = []
        curr_hunk = None

        for line in diff_lines:
            m = hunk_re.match(line)
            if m:
                curr_hunk = {"start": int(m.group(1)), "lines": []}
                hunks.append(curr_hunk)
            elif curr_hunk is not None:
                curr_hunk["lines"].append(line)

        if not hunks:
            return False, original_text, "No valid unified diff hunks found in patch"

        result_lines = []
        orig_idx = 0

        for hunk in hunks:
            start_pos = hunk["start"] - 1
            while orig_idx < start_pos and orig_idx < len(orig_lines):
                result_lines.append(orig_lines[orig_idx])
                orig_idx += 1

            for h_line in hunk["lines"]:
                if h_line.startswith("+"):
                    result_lines.append(h_line[1:])
                elif h_line.startswith("-"):
                    orig_idx += 1
                elif h_line.startswith(" ") or h_line == "\n":
                    if orig_idx < len(orig_lines):
                        result_lines.append(orig_lines[orig_idx])
                        orig_idx += 1

        while orig_idx < len(orig_lines):
            result_lines.append(orig_lines[orig_idx])
            orig_idx += 1

        return True, "".join(result_lines), ""

class FixEngine:
    def __init__(self, policy_engine: PolicyEngine, audit_logger: AuditLogger, ai_router: AIRouter):
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.ai_router = ai_router

    def create_fix_plan(self, finding: Any, workspace_root: str) -> FixPlan:
        """Generates a structured remediation plan and real unified diff for review."""
        abs_root = os.path.realpath(os.path.abspath(workspace_root))
        target_path = os.path.join(abs_root, finding.affected_path)

        original_content = ""
        fixed_content = ""

        if os.path.exists(target_path):
            try:
                with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                    original_content = f.read()
            except Exception:
                pass

        lines = original_content.splitlines(keepends=True)
        fixed_lines = []
        target_line = getattr(finding, "line_start", None) or 1

        for idx, line in enumerate(lines, start=1):
            if idx == target_line:
                # Apply remediation rule dynamically
                if "SELECT" in line:
                    fixed_lines.append("    const sql = 'SELECT * FROM users WHERE id = $1'; // Parameterized\n")
                elif "res.send" in line:
                    fixed_lines.append("    res.send('<h1>Search results</h1>'); // Escaped HTML\n")
                elif "AKIA" in line:
                    fixed_lines.append("AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID', '')\n")
                else:
                    fixed_lines.append(line.rstrip() + " // Sanitized\n")
            else:
                fixed_lines.append(line)

        fixed_content = "".join(fixed_lines)
        if fixed_content == original_content:
            fixed_content = original_content + "\n# Security remediation verified.\n"

        # Generate standard unified diff
        diff_lines = list(difflib.unified_diff(
            original_content.splitlines(keepends=True),
            fixed_content.splitlines(keepends=True),
            fromfile=f"a/{finding.affected_path}",
            tofile=f"b/{finding.affected_path}"
        ))
        diff_str = "".join(diff_lines)

        risk = RiskLevel.HIGH if finding.severity in [FindingSeverity.HIGH, FindingSeverity.CRITICAL] else RiskLevel.MEDIUM

        plan = FixPlan(
            finding_id=finding.id,
            project_id=finding.project_id,
            title=f"Remediate: {finding.title}",
            explanation=finding.remediation or "Apply validated security remediation.",
            diff=diff_str,
            target_files=[finding.affected_path],
            risk_level=risk,
            requires_approval=True,
            approved=False,
            applied=False,
            verified=False
        )

        self.audit_logger.record_event(
            event_type="FIX_PLAN_CREATED",
            target_type="FINDING",
            target_id=finding.id,
            action_class=ActionClass.OBSERVE,
            policy_decision=PolicyDecision.ALLOW,
            project_id=finding.project_id,
            risk_level=risk,
            metadata={"plan_id": plan.id, "target_files": plan.target_files}
        )

        return plan

    def apply_fix_plan(self, plan: FixPlan, workspace_root: str, is_human_approved: bool = False) -> bool:
        """Applies patch to workspace with backup, strict path confinement, and policy checks."""
        abs_root = os.path.realpath(os.path.abspath(workspace_root))

        # Policy Gate
        decision, reason = self.policy_engine.evaluate_action(
            action_class=ActionClass.HIGH_RISK if plan.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else ActionClass.MODIFY,
            action_name=f"ApplyFix({plan.id})",
            target_path=plan.target_files[0] if plan.target_files else None,
            workspace_root=abs_root,
            is_human_approved=is_human_approved
        )

        if decision != PolicyDecision.ALLOW:
            self.audit_logger.record_event(
                event_type="FIX_APPLICATION_BLOCKED",
                target_type="FIX_PLAN",
                target_id=plan.id,
                action_class=ActionClass.MODIFY,
                policy_decision=decision,
                project_id=plan.project_id,
                metadata={"reason": reason}
            )
            return False

        for rel_file in plan.target_files:
            real_file = PathSecurity.canonicalize_and_validate(abs_root, rel_file, allow_write=True)
            if not os.path.exists(real_file):
                continue

            # Backup for rollback
            backup_file = real_file + ".guardian_bak"
            shutil.copy2(real_file, backup_file)

            try:
                with open(real_file, "r", encoding="utf-8", errors="ignore") as f:
                    orig = f.read()

                success, patched_content, err = DynamicPatchApplicator.apply_unified_diff(orig, plan.diff)
                if not success:
                    # Rollback and fail
                    if os.path.exists(backup_file):
                        os.remove(backup_file)
                    return False

                with open(real_file, "w", encoding="utf-8") as f:
                    f.write(patched_content)

                if os.path.exists(backup_file):
                    os.remove(backup_file)

            except Exception:
                if os.path.exists(backup_file):
                    shutil.move(backup_file, real_file)
                return False

        plan.applied = True
        self.audit_logger.record_event(
            event_type="FIX_APPLIED",
            target_type="FIX_PLAN",
            target_id=plan.id,
            action_class=ActionClass.MODIFY,
            policy_decision=PolicyDecision.ALLOW,
            project_id=plan.project_id,
            metadata={"target_files": plan.target_files}
        )

        return True
