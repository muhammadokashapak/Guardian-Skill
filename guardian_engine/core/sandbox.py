import os
import shutil
import tempfile
import subprocess
import time
from typing import List, Dict, Optional, Tuple, Any
from .policy_engine import PolicyEngine
from .models import PolicyDecision
from .secret_redactor import SecretRedactor

class SandboxExecutionResult:
    def __init__(
        self,
        command: List[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        duration_sec: float,
        timed_out: bool = False,
        blocked_by_policy: bool = False,
        policy_reason: str = "",
        is_isolated_worktree: bool = False
    ):
        self.command = command
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.duration_sec = duration_sec
        self.timed_out = timed_out
        self.blocked_by_policy = blocked_by_policy
        self.policy_reason = policy_reason
        self.is_isolated_worktree = is_isolated_worktree

    def to_dict(self) -> Dict[str, Any]:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_sec": self.duration_sec,
            "timed_out": self.timed_out,
            "blocked_by_policy": self.blocked_by_policy,
            "policy_reason": self.policy_reason,
            "is_isolated_worktree": self.is_isolated_worktree,
        }

class SandboxedRunner:
    def __init__(
        self,
        workspace_root: str,
        policy_engine: Optional[PolicyEngine] = None,
        timeout_seconds: int = 30,
        max_output_bytes: int = 100000
    ):
        self.workspace_root = os.path.realpath(os.path.abspath(workspace_root))
        self.policy_engine = policy_engine or PolicyEngine()
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def run_command(
        self,
        command: List[str],
        cwd: Optional[str] = None,
        env_vars: Optional[Dict[str, str]] = None
    ) -> SandboxExecutionResult:
        # 1. Deterministic Policy Check
        decision, reason = self.policy_engine.validate_command(command)
        if decision != PolicyDecision.ALLOW:
            return SandboxExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Policy Block: {reason}",
                duration_sec=0.0,
                blocked_by_policy=True,
                policy_reason=reason
            )

        # 2. Path verification for working directory
        work_dir = cwd or self.workspace_root
        if not os.path.realpath(work_dir).startswith(self.workspace_root):
            return SandboxExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Security Error: Working dir '{work_dir}' is outside sandbox root",
                duration_sec=0.0,
                blocked_by_policy=True,
                policy_reason="Working directory outside sandbox boundary"
            )

        # 3. Clean environment (sanitize secrets)
        safe_env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
            "TEMP": os.environ.get("TEMP", ""),
            "TMP": os.environ.get("TMP", ""),
            "GUARDIAN_SANDBOX": "1"
        }
        if env_vars:
            safe_env.update(env_vars)

        start_time = time.time()
        try:
            # Execute with NO shell=True
            process = subprocess.Popen(
                command,
                cwd=work_dir,
                env=safe_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False
            )

            stdout, stderr = process.communicate(timeout=self.timeout_seconds)
            duration = time.time() - start_time

            # Redact secrets from output
            redacted_stdout, _ = SecretRedactor.redact(stdout[:self.max_output_bytes])
            redacted_stderr, _ = SecretRedactor.redact(stderr[:self.max_output_bytes])

            return SandboxExecutionResult(
                command=command,
                exit_code=process.returncode,
                stdout=redacted_stdout,
                stderr=redacted_stderr,
                duration_sec=round(duration, 3)
            )

        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            return SandboxExecutionResult(
                command=command,
                exit_code=-1,
                stdout=SecretRedactor.redact(stdout[:self.max_output_bytes])[0],
                stderr="Execution timed out in sandbox",
                duration_sec=float(self.timeout_seconds),
                timed_out=True
            )
        except Exception as ex:
            return SandboxExecutionResult(
                command=command,
                exit_code=-1,
                stdout="",
                stderr=f"Sandbox execution failure: {str(ex)}",
                duration_sec=round(time.time() - start_time, 3)
            )

    def run_in_disposable_worktree(
        self,
        source_directory: str,
        command: List[str]
    ) -> SandboxExecutionResult:
        """
        Creates a disposable, isolated worktree copy of source_directory,
        executes the command inside it, and ensures complete cleanup on exit.
        """
        temp_dir = tempfile.mkdtemp(prefix="guardian_worktree_")
        try:
            # Clone files to temporary workspace
            for item in os.listdir(source_directory):
                s = os.path.join(source_directory, item)
                d = os.path.join(temp_dir, item)
                if os.path.isdir(s):
                    shutil.copytree(s, d, ignore=shutil.ignore_patterns(".git", "node_modules", "vendor"))
                else:
                    shutil.copy2(s, d)

            # Create runner scoped to temp_dir
            runner = SandboxedRunner(temp_dir, self.policy_engine, self.timeout_seconds)
            res = runner.run_command(command, cwd=temp_dir)
            res.is_isolated_worktree = True
            return res
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
