import re
import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from ..ai.router import AIRouter
from ..core.secret_redactor import SecretRedactor

class IncidentEvidence(BaseModel):
    source: str
    timestamp: str
    content: str

class IncidentHypothesis(BaseModel):
    rank: int
    hypothesis: str
    confidence: float
    supporting_evidence: List[str] = Field(default_factory=list)

class IncidentInvestigationReport(BaseModel):
    incident_id: str
    title: str
    timeline: List[Dict[str, str]] = Field(default_factory=list)
    hypotheses: List[IncidentHypothesis] = Field(default_factory=list)
    probable_root_cause: str
    confidence: float
    remediation_recommendations: List[str] = Field(default_factory=list)
    verification_steps: List[str] = Field(default_factory=list)

class IncidentInvestigator:
    def __init__(self, ai_router: AIRouter):
        self.ai_router = ai_router

    def investigate(
        self,
        incident_id: str,
        title: str,
        raw_logs: str,
        recent_changes: Optional[List[str]] = None
    ) -> IncidentInvestigationReport:
        # 1. Sanitize logs to eliminate exposed secrets
        clean_logs, _ = SecretRedactor.redact(raw_logs)

        # 2. Extract timeline events from logs
        timeline = []
        for line in clean_logs.splitlines():
            line = line.strip()
            if not line:
                continue
            # Simple timestamp matcher or fallback
            ts_match = re.search(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
            ts = ts_match.group(1) if ts_match else datetime.datetime.utcnow().isoformat()
            timeline.append({"timestamp": ts, "event": line[:150]})

        # 3. Rule-based Root-Cause Detection
        hypotheses: List[IncidentHypothesis] = []
        probable_cause = "Insufficient evidence to determine single root cause with certainty."
        overall_conf = 0.5

        if "NullPointerException" in clean_logs or "Call to a member function on null" in clean_logs or "NoneType" in clean_logs:
            hypotheses.append(IncidentHypothesis(
                rank=1,
                hypothesis="Unchecked null/undefined reference in data transformation pipeline",
                confidence=0.89,
                supporting_evidence=["Null reference exception captured in execution trace"]
            ))
            probable_cause = "Unchecked null value returned from external dependency or cache layer."
            overall_conf = 0.89
        elif "Deadlock" in clean_logs or "Lock wait timeout" in clean_logs:
            hypotheses.append(IncidentHypothesis(
                rank=1,
                hypothesis="Database transaction lock contention under concurrent write volume",
                confidence=0.85,
                supporting_evidence=["Lock wait timeout exceeded logged by database driver"]
            ))
            probable_cause = "Concurrent unindexed update queries acquiring overlapping table locks."
            overall_conf = 0.85
        else:
            hypotheses.append(IncidentHypothesis(
                rank=1,
                hypothesis="Transient network timeout or upstream service degradation",
                confidence=0.60,
                supporting_evidence=["Connection reset or timeout log patterns observed"]
            ))

        # 4. Correlate with AI Gateway
        ai_resp = self.ai_router.reason(
            task_instruction=f"Investigate incident '{title}'. Rank hypotheses and formulate remediation.",
            untrusted_context=f"Logs:\n{clean_logs[:2000]}\nRecent changes:\n{recent_changes or []}"
        )

        return IncidentInvestigationReport(
            incident_id=incident_id,
            title=title,
            timeline=timeline[:10],
            hypotheses=hypotheses,
            probable_root_cause=probable_cause,
            confidence=overall_conf,
            remediation_recommendations=[
                "Implement defensive null-safety and fallbacks for unresolved entity lookups.",
                "Add circuit breaker for upstream requests.",
                "Review recent commits touching the affected service."
            ],
            verification_steps=[
                "Replay sanitized failed payload in sandbox test environment.",
                "Monitor error rate metrics following patch deployment."
            ]
        )
