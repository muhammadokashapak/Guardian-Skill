import json
from typing import Optional
from .base_provider import BaseAIProvider, AICompletionResponse

class MockOfflineAIProvider(BaseAIProvider):
    def __init__(self, model_name: str = "guardian-local-offline"):
        self.model = model_name

    def provider_name(self) -> str:
        return "mock-offline"

    def complete(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        max_tokens: int = 2000,
        temperature: float = 0.2
    ) -> AICompletionResponse:
        # Generate structured engineering reasoning based on prompt keywords
        p_lower = prompt.lower()

        if "fix" in p_lower or "remediation" in p_lower:
            response_text = """### Root Cause Analysis
The issue stems from unsanitized input concatenated into an operation without parameter binding or boundary checking.

### Remediation Plan
1. Apply parameterized input bindings.
2. Ensure strict type validation and canonicalization.
3. Validate tests pass before deployment.

### Suggested Diff
```diff
- $query = "SELECT * FROM users WHERE id = " . $id;
+ $query = DB::select("SELECT * FROM users WHERE id = ?", [$id]);
```
"""
        elif "incident" in p_lower or "stack trace" in p_lower:
            response_text = """### Incident Investigation
- Evidence: Null pointer exception during authentication handler execution.
- Probable Root Cause: Missing null check when resolving user token from cache.
- Confidence: 0.88 (Hypothesis Ranked #1)
- Recommended Remediation: Add null safe navigation and fallback session retrieval.
"""
        elif "impact" in p_lower:
            response_text = """### Change Impact Assessment
- Affected Components: AuthController, UserService, ApiTokenModel
- Backward Compatibility: Compatible if new parameter is optional
- Migration Required: None
- Risk Rating: LOW
"""
        else:
            response_text = """### Guardian AI Engineering Reasoning
Evidence analyzed from codebase and security findings.
Confidence: 0.90
Remediation: Follow security best practices and verify with automated tests.
"""

        return AICompletionResponse(
            provider_name=self.provider_name(),
            model_name=self.model,
            content=response_text,
            prompt_tokens=len(prompt) // 4,
            completion_tokens=len(response_text) // 4,
            total_tokens=(len(prompt) + len(response_text)) // 4
        )
