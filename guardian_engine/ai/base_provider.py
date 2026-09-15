import abc
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

class AICompletionResponse(BaseModel):
    provider_name: str
    model_name: str
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    raw_response: Optional[Dict[str, Any]] = None

class BaseAIProvider(abc.ABC):
    @abc.abstractmethod
    def provider_name(self) -> str:
        pass

    @abc.abstractmethod
    def complete(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        max_tokens: int = 2000,
        temperature: float = 0.2
    ) -> AICompletionResponse:
        pass
