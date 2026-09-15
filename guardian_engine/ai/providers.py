import os
import json
from typing import Optional
import requests
from .base_provider import BaseAIProvider, AICompletionResponse

class OllamaProvider(BaseAIProvider):
    def __init__(self, host: str = "http://localhost:11434", model: str = "llama3"):
        self.host = os.environ.get("OLLAMA_HOST", host)
        self.model = os.environ.get("OLLAMA_MODEL", model)

    def provider_name(self) -> str:
        return "ollama"

    def complete(self, prompt: str, system_instruction: Optional[str] = None, max_tokens: int = 2000, temperature: float = 0.2) -> AICompletionResponse:
        url = f"{self.host}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_instruction or "",
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens}
        }
        resp = requests.post(url, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        return AICompletionResponse(
            provider_name=self.provider_name(),
            model_name=self.model,
            content=data.get("response", ""),
            raw_response=data
        )

class OpenAIProvider(BaseAIProvider):
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model

    def provider_name(self) -> str:
        return "openai"

    def complete(self, prompt: str, system_instruction: Optional[str] = None, max_tokens: int = 2000, temperature: float = 0.2) -> AICompletionResponse:
        import openai
        client = openai.OpenAI(api_key=self.api_key)
        messages = []
        if system_instruction:
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})

        res = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature
        )
        msg = res.choices[0].message.content or ""
        return AICompletionResponse(
            provider_name=self.provider_name(),
            model_name=self.model,
            content=msg,
            prompt_tokens=res.usage.prompt_tokens if res.usage else 0,
            completion_tokens=res.usage.completion_tokens if res.usage else 0,
            total_tokens=res.usage.total_tokens if res.usage else 0
        )

class GeminiProvider(BaseAIProvider):
    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-1.5-pro"):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.model = model

    def provider_name(self) -> str:
        return "gemini"

    def complete(self, prompt: str, system_instruction: Optional[str] = None, max_tokens: int = 2000, temperature: float = 0.2) -> AICompletionResponse:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        parts = []
        if system_instruction:
            parts.append({"text": f"SYSTEM: {system_instruction}\n\n"})
        parts.append({"text": prompt})
        payload = {"contents": [{"parts": parts}]}
        resp = requests.post(url, json=payload, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        candidates = data.get("candidates", [])
        text = ""
        if candidates:
            text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
        return AICompletionResponse(
            provider_name=self.provider_name(),
            model_name=self.model,
            content=text,
            raw_response=data
        )

class ClaudeProvider(BaseAIProvider):
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model

    def provider_name(self) -> str:
        return "claude"

    def complete(self, prompt: str, system_instruction: Optional[str] = None, max_tokens: int = 2000, temperature: float = 0.2) -> AICompletionResponse:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_instruction or "You are an AI Security Engineer.",
            "messages": [{"role": "user", "content": prompt}]
        }
        resp = requests.post("https://api.anthropic.com/v1/messages", json=payload, headers=headers, timeout=60)
        resp.raise_for_status()
        data = resp.json()
        text = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                text += block.get("text", "")
        return AICompletionResponse(
            provider_name=self.provider_name(),
            model_name=self.model,
            content=text,
            raw_response=data
        )
