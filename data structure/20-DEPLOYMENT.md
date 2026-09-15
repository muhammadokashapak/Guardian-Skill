# Deployment & Runtime

## Preferred runtime
Run Guardian in a dedicated least-privileged environment or sandbox/worktree.

## Secrets
Inject secrets through the host secret manager/environment. Never commit them.

## Production principle
The Guardian should normally analyze production evidence without direct production write access.

## Network
Default deny with explicit provider/tool allowlist.

## Backups
Maintain backups/snapshots before significant modifications.

## Updates
Pin and review Guardian dependencies. Run self-audit and regression suite after upgrades.

## Local mode
Ollama can be used for privacy/cost-sensitive analysis where model quality is sufficient. Cloud models can be used for tasks requiring stronger reasoning, subject to configured data policy.
