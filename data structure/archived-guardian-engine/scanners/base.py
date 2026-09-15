import abc
import hashlib
from typing import List
from ..core.models import Finding, FindingSeverity, FindingStatus, FindingEvidence

class BaseScanner(abc.ABC):
    @abc.abstractmethod
    def name(self) -> str:
        pass

    @abc.abstractmethod
    def scan(self, project_id: str, scan_id: str, workspace_root: str) -> List[Finding]:
        pass

    @classmethod
    def generate_fingerprint(cls, category: str, affected_path: str, rule_id: str, line: int = 0) -> str:
        """Generates a stable, reproducible SHA-256 fingerprint for finding deduplication."""
        token = f"{category}|{affected_path.replace(chr(92), '/')}|{rule_id}|{line}"
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
