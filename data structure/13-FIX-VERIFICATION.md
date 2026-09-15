# Fix & Verification Engine

## Lifecycle
Finding → Root Cause → Fix Plan → Risk Assessment → Approval → Patch → Diff Review → Tests → Independent Verification → Re-scan → Resolve/Rollback.

## Fix plan
- finding_id
- root_cause
- affected_files
- proposed_changes
- risk_level
- approval_required
- tests
- rollback_plan
- verification_criteria

## Verification rules
- Verify the original issue is gone.
- Verify intended behavior remains.
- Run relevant regression checks.
- Re-scan affected security areas.
- Record evidence.
- Never claim success without evidence.

## Rollback
If verification fails, revert the controlled patch where possible and keep the failed attempt in the audit trail.
