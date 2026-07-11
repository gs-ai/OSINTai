import json
from typing import Optional, Dict, Any, List

import httpx

class OllamaAPI:
    """Ollama API client for LLM analysis and embeddings."""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url.rstrip("/")

    def generate_json(self, model: str, prompt: str, timeout_s: float = 60.0) -> Optional[Dict[str, Any]]:
        """Generate JSON response from model."""
        return self._run_sync(self.async_generate_json, model, prompt, timeout_s)

    async def async_generate_json(self, model: str, prompt: str, timeout_s: float = 60.0) -> Optional[Dict[str, Any]]:
        """Generate JSON without blocking the crawler event loop."""
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.2,
                "top_p": 0.8,
                "num_ctx": 8192
            }
        }
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            response_text = data.get("response", "")
            return self._extract_json(response_text)
        except Exception:
            return None

    def embed(self, model: str, input_text: str, timeout_s: float = 30.0) -> Optional[List[float]]:
        """Generate embeddings for text."""
        return self._run_sync(self.async_embed, model, input_text, timeout_s)

    async def async_embed(self, model: str, input_text: str, timeout_s: float = 30.0) -> Optional[List[float]]:
        """Generate embeddings without blocking the crawler event loop."""
        url = f"{self.base_url}/api/embeddings"
        payload = {"model": model, "prompt": input_text}
        try:
            async with httpx.AsyncClient(timeout=timeout_s) as client:
                r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            vec = data.get("embedding")
            return vec if isinstance(vec, list) else None
        except Exception:
            return None

    def analyze(self, url: str, title: str, text: str, model: str = "osint-tuned-v3:latest") -> Optional[Dict[str, Any]]:
        """Analyze content for intelligence value."""
        prompt = f"""Analyze this webpage for OSINT intelligence value.

URL: {url}
Title: {title}

Content:
{text[:3000]}

Return JSON with:
- intelligence_score: 1-10 (10 being highest value)
- categories: list of relevant categories
- summary: brief summary
- indicators: any notable indicators found"""

        return self.generate_json(model, prompt, timeout_s=120.0)

    @staticmethod
    def _run_sync(async_fn, *args):
        try:
            import asyncio

            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(async_fn(*args))
        raise RuntimeError("Use async_generate_json/async_embed from an active event loop")

    def _extract_json(self, s: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from text response."""
        start = s.find("{")
        end = s.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        blob = s[start:end+1]
        try:
            return json.loads(blob)
        except Exception:
            return None
