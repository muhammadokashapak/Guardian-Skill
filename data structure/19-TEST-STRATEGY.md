# Test Strategy

## Test layers
1. Unit
2. Integration
3. Policy-engine tests
4. Agent contract tests
5. Prompt-injection corpus
6. Malicious repository corpus
7. Path/symlink tests
8. Secret-redaction tests
9. Command-policy tests
10. Network-policy tests
11. Regression tests
12. End-to-end sandbox tests

## Security test corpus
Include harmless fixtures demonstrating:
- fake prompt-injection instructions
- deceptive filenames
- path traversal attempts
- symlink escape attempts
- fake credentials
- dangerous command requests
- malicious-looking dependency scripts
- oversized files
- binary/unexpected formats

## Quality gate
A release is blocked if critical Guardian security tests fail.
