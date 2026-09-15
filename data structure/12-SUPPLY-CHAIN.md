# Supply Chain Security Guardian

## Scope
- Package manifests
- Lockfiles
- Dependency versions
- Lifecycle scripts
- Container images
- Dockerfiles
- CI/CD workflows
- Build permissions
- Artifact sources
- Secrets and tokens

## Controls
- Prefer lockfiles.
- Review dependency changes.
- Minimize install privileges.
- Isolate package installation.
- Restrict network access.
- Detect suspicious scripts/configuration.
- Audit CI token permissions.
- Flag unpinned or unexpected sources.
- Keep Guardian dependencies minimal and pinned where practical.

## Do not
- Automatically replace dependencies solely because they are outdated.
- Automatically execute arbitrary package scripts outside an isolated approved environment.
