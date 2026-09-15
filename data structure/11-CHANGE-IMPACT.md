# AI Change Impact Analyzer

## Input example
“Replace JWT authentication with OAuth.”

## Analysis
1. Parse requested change.
2. Identify architectural concepts.
3. Search codebase graph.
4. Identify direct and indirect dependencies.
5. Map APIs, database, UI, integrations and tests.
6. Identify security implications.
7. Produce migration sequence.

## Output
- Directly affected files/components
- Indirectly affected components
- API/schema changes
- Security risks
- Test impact
- Data migration requirements
- Rollback considerations
- Suggested implementation order

## Guardrail
Impact analysis is advisory. It must not silently modify the project.
