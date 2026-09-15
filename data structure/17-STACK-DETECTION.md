# Stack Detection

## Detection signals
- package.json / lockfiles
- composer.json / composer.lock
- pyproject.toml / requirements files
- Dockerfile / compose files
- framework configuration
- source conventions
- database migration directories
- CI workflow files

## Initial profiles
- Next.js / React / TypeScript
- Node.js
- Laravel / PHP
- Python / FastAPI
- MySQL / PostgreSQL
- Docker
- Full-stack combinations

## Design
Use detectors to select checks. Do not assume a framework solely from one filename if conflicting evidence exists.
