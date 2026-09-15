# AI Production Incident Investigator

## Goal
Reduce time to understand production incidents without giving the AI uncontrolled production access.

## Evidence sources
- Logs
- Stack traces
- Metrics
- Traces
- Deployment metadata
- Git history
- Change requests
- Incident notes
- Sanitized database/query evidence

## Workflow
Collect → Normalize → Correlate → Timeline → Hypotheses → Evidence scoring → Root-cause candidate → Recommended verification.

## Safety
- Read-only by default.
- No production command execution by default.
- No secret retrieval.
- No destructive remediation.
- Production actions require separate explicit approval and infrastructure controls.

## Output
- Incident summary
- Timeline
- Affected components
- Ranked hypotheses
- Evidence for/against each hypothesis
- Recommended safe checks
- Remediation plan
- Confidence and unknowns
