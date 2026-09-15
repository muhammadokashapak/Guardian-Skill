import os
import json
import hashlib
import datetime
from typing import List, Optional, Dict, Any
from .models import AuditEvent, ActionClass, PolicyDecision, RiskLevel
from .secret_redactor import SecretRedactor

class AuditLogger:
    def __init__(self, log_file_path: Optional[str] = None):
        self.log_file_path = log_file_path
        self.events: List[AuditEvent] = []
        self.last_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
        self._load_or_init()

    def _load_or_init(self):
        if self.log_file_path and os.path.exists(self.log_file_path):
            try:
                with open(self.log_file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            event = AuditEvent(**data)
                            self.events.append(event)
                            self.last_hash = event.hash
            except Exception:
                pass

    def record_event(
        self,
        event_type: str,
        target_type: str,
        target_id: str,
        action_class: ActionClass = ActionClass.OBSERVE,
        policy_decision: PolicyDecision = PolicyDecision.ALLOW,
        risk_level: RiskLevel = RiskLevel.LOW,
        actor_type: str = "SYSTEM",
        actor_id: str = "guardian-daemon",
        organization_id: str = "org-default",
        project_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        clean_metadata = metadata or {}
        # Ensure any secret in metadata is redacted
        metadata_str = json.dumps(clean_metadata)
        redacted_meta_str, _ = SecretRedactor.redact(metadata_str)
        redacted_metadata = json.loads(redacted_meta_str)

        # Build payload for hash chaining using fixed timestamp string
        now = datetime.datetime.utcnow()
        now_str = now.strftime("%Y-%m-%dT%H:%M:%S.%f")
        payload = f"{self.last_hash}|{now_str}|{event_type}|{target_id}|{policy_decision.value}|{action_class.value}"
        current_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        event = AuditEvent(
            organization_id=organization_id,
            project_id=project_id,
            actor_type=actor_type,
            actor_id=actor_id,
            event_type=event_type,
            target_type=target_type,
            target_id=target_id,
            action_class=action_class,
            policy_decision=policy_decision,
            risk_level=risk_level,
            metadata_json=redacted_metadata,
            prev_hash=self.last_hash,
            hash=current_hash,
            created_at=now
        )

        self.last_hash = current_hash
        self.events.append(event)

        # Append to log file if configured
        if self.log_file_path:
            try:
                with open(self.log_file_path, "a", encoding="utf-8") as f:
                    f.write(event.model_dump_json() + "\n")
            except Exception:
                pass

        return event

    def verify_integrity(self) -> bool:
        """Verifies the SHA-256 hash chain across all audit events."""
        if not self.events:
            return True
        prev = self.events[0].prev_hash
        for event in self.events:
            now_str = event.created_at.strftime("%Y-%m-%dT%H:%M:%S.%f")
            payload = f"{prev}|{now_str}|{event.event_type}|{event.target_id}|{event.policy_decision.value}|{event.action_class.value}"
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if event.hash != expected or event.prev_hash != prev:
                return False
            prev = event.hash
        return True
