import json
import ipaddress
from typing import Optional, Dict, Any, List
from urllib.parse import urlsplit

import httpx


def _validate_local_base_url(value: str) -> str:
    """Accept only credential-free loopback Ollama endpoints."""
    parsed = urlsplit((value or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Ollama endpoint must be an HTTP(S) loopback URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Ollama endpoint cannot contain credentials, a query, or a fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("Ollama endpoint must not contain a path")
    host = parsed.hostname.lower()
    if host != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("Ollama endpoint must resolve to a loopback address")
        except ValueError as exc:
            if "loopback" in str(exc):
                raise
            raise ValueError("Ollama endpoint must resolve to a loopback address") from exc
    return value.rstrip("/")

class OllamaAPI:
    """Ollama API client for LLM analysis and embeddings."""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = _validate_local_base_url(base_url)
        self.response_counts = {}

    def generate_json(self, model: str, prompt: str, timeout_s: float = 60.0) -> Optional[Dict[str, Any]]:
        """Generate JSON response from model."""
        return self._run_sync(self.async_generate_json, model, prompt, timeout_s)

    async def async_generate_json(self, model: str, prompt: str, timeout_s: float = 60.0) -> Optional[Dict[str, Any]]:
        """Generate JSON without blocking the crawler event loop."""
        result = await self.async_generate_result(model, prompt, timeout_s)
        return result["payload"]

    async def async_generate_result(self, model: str, prompt: str, timeout_s: float = 60.0):
        """Return payload and a distinct outcome for every attempted model call."""
        def outcome(status, payload=None):
            counts = self.response_counts.setdefault(model, {})
            counts[status] = counts.get(status, 0) + 1
            return {"status": status, "model": model, "payload": payload}

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
            async with httpx.AsyncClient(timeout=timeout_s, trust_env=False) as client:
                r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            if not isinstance(data, dict) or "response" not in data:
                return outcome("missing")
            response_text = data["response"]
            if not isinstance(response_text, str):
                return outcome("invalid")
            if not response_text.strip():
                return outcome("empty")
            parsed = self._extract_json(response_text)
            if parsed == {}:
                return outcome("empty")
            return outcome("ok", parsed) if isinstance(parsed, dict) else outcome("invalid")
        except httpx.TimeoutException:
            return outcome("timed_out")
        except (ValueError, TypeError):
            return outcome("invalid")
        except Exception:
            return outcome("error")

    def embed(self, model: str, input_text: str, timeout_s: float = 30.0) -> Optional[List[float]]:
        """Generate embeddings for text."""
        return self._run_sync(self.async_embed, model, input_text, timeout_s)

    async def async_embed(self, model: str, input_text: str, timeout_s: float = 30.0) -> Optional[List[float]]:
        """Generate embeddings without blocking the crawler event loop."""
        url = f"{self.base_url}/api/embeddings"
        payload = {"model": model, "prompt": input_text}
        try:
            async with httpx.AsyncClient(timeout=timeout_s, trust_env=False) as client:
                r = await client.post(url, json=payload)
            r.raise_for_status()
            data = r.json()
            vec = data.get("embedding")
            return vec if isinstance(vec, list) else None
        except Exception:
            return None

    async def async_generate_text(self, model: str, prompt: str, timeout_s: float = 60.0) -> Optional[str]:
        """Free-text generation. Same endpoint and options as generate_json, without format=json."""
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "top_p": 0.8,
                "num_ctx": 8192
            }
        }
        try:
            async with httpx.AsyncClient(timeout=timeout_s, trust_env=False) as client:
                r = await client.post(url, json=payload)
            r.raise_for_status()
            return r.json().get("response", "")
        except Exception:
            return None

    def health(self, timeout_s: float = 5.0) -> Dict[str, Any]:
        """Is the local model server reachable, and what does it have loaded?

        Reported at startup so an unreachable server is visible before the crawl rather
        than showing up as pages that silently produced no analysis.
        """
        try:
            with httpx.Client(timeout=timeout_s, trust_env=False) as client:
                r = client.get(f"{self.base_url}/api/tags")
            r.raise_for_status()
            models = [m.get("name", "") for m in r.json().get("models", []) if isinstance(m, dict)]
            return {"reachable": True, "models": sorted(n for n in models if n), "error": ""}
        except Exception as exc:
            return {"reachable": False, "models": [], "error": str(exc)}

    def list_models(self, timeout_s: float = 5.0) -> List[str]:
        return self.health(timeout_s)["models"]

    def has_model(self, model: str, timeout_s: float = 5.0) -> bool:
        """Exact name first, then the bare name, since ':latest' is often left off."""
        available = self.list_models(timeout_s)
        if model in available:
            return True
        base = model.split(":")[0]
        return any(name.split(":")[0] == base for name in available)

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
