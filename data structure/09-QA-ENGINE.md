# AI QA Engineer

## Inputs
- Requirements
- User flows
- Codebase graph
- API contracts
- Existing tests
- Findings
- Change request

## Test generation
Generate:
- happy paths
- negative cases
- boundary cases
- authorization cases
- API contract cases
- regression cases
- security-focused cases
- integration cases

## Test execution safety
Tests execute only through policy-approved commands and isolated environments.

## Test case schema
- id
- objective
- preconditions
- steps
- expected_result
- risk
- automation_status
- evidence

## Quality gates
A fix is not verified merely because one test passes. Use relevant regression tests plus targeted verification and, where appropriate, static/security re-scan.
