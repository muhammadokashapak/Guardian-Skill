# Error Handling & Fail-Closed Rules

## Principles
- Policy service unavailable → deny action.
- Scanner unavailable → report incomplete scan; do not claim clean.
- AI unavailable → preserve deterministic results.
- Verification unavailable → do not mark fix verified.
- Repository changed during operation → invalidate/re-check snapshot.
- Unexpected tool output → treat as untrusted evidence.
- Timeout → stop safely and record state.

## User-facing status
Use explicit states:
queued, running, completed, partial, blocked, failed, awaiting_approval, verified, rejected, rolled_back.
