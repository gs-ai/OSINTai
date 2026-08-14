import asyncio
import secrets
from collections.abc import Callable
from typing import Dict, Optional
from urllib.parse import urljoin

import httpx

from .proxy_pool import ProxyPool


class FetchRejected(RuntimeError):
    """Raised when a response violates the crawler's content safety policy."""


REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 10
_RANDOM = secrets.SystemRandom()


class AsyncFetcher:
    def __init__(
        self,
        user_agents,
        proxy_pool: Optional[ProxyPool] = None,
        timeout_s: float = 20.0,
        min_delay_s: float = 0.2,
        max_delay_s: float = 1.2,
        retries: int = 2,
        max_response_bytes: int = 2_000_000,
    ):
        self.user_agents = user_agents or ["Mozilla/5.0"]
        self.proxy_pool = proxy_pool
        self.timeout_s = timeout_s
        self.min_delay_s = min_delay_s
        self.max_delay_s = max_delay_s
        self.retries = retries
        self.max_response_bytes = max(1, max_response_bytes)

    def _headers(self) -> Dict[str, str]:
        ua = secrets.choice(self.user_agents)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    async def _bounded_get(
        self,
        client: httpx.AsyncClient,
        url: str,
        request_kwargs: dict,
        redirect_validator: Optional[Callable[[str], bool]] = None,
    ) -> httpx.Response:
        """Fetch HTML while validating every redirect before the next request."""
        current_url = url
        for redirect_count in range(MAX_REDIRECTS + 1):
            async with client.stream(
                "GET",
                current_url,
                timeout=self.timeout_s,
                follow_redirects=False,
                **request_kwargs,
            ) as resp:
                if resp.status_code in REDIRECT_STATUSES:
                    location = resp.headers.get("location", "").strip()
                    if not location:
                        return self._empty_response(resp)
                    if redirect_count >= MAX_REDIRECTS:
                        raise FetchRejected(f"redirect limit exceeded ({MAX_REDIRECTS})")
                    next_url = urljoin(str(resp.url), location)
                    if redirect_validator is not None and not redirect_validator(next_url):
                        raise FetchRejected(f"redirect outside authorized scope: {next_url}")
                    current_url = next_url
                    continue

                if resp.status_code != 200:
                    # Status is all the crawler needs for unsuccessful responses;
                    # do not receive their response bodies.
                    return self._empty_response(resp)

                content_type = (
                    resp.headers.get("content-type", "").partition(";")[0].strip().lower()
                )
                if content_type not in {"text/html", "application/xhtml+xml"}:
                    raise FetchRejected(
                        f"content type {content_type or '(missing)'} is not HTML/XHTML"
                    )

                content_length = resp.headers.get("content-length")
                if content_length and content_length.isdigit():
                    if int(content_length) > self.max_response_bytes:
                        raise FetchRejected(
                            f"response exceeds {self.max_response_bytes} byte limit"
                        )

                content = bytearray()
                async for chunk in resp.aiter_bytes():
                    if len(content) + len(chunk) > self.max_response_bytes:
                        raise FetchRejected(
                            f"response exceeds {self.max_response_bytes} byte limit"
                        )
                    content.extend(chunk)

                # aiter_bytes() returns decoded bytes; remove transport encodings so
                # the reconstructed buffered response is not decoded a second time.
                headers = dict(resp.headers)
                headers.pop("content-encoding", None)
                headers.pop("content-length", None)
                return httpx.Response(
                    status_code=resp.status_code,
                    headers=headers,
                    content=bytes(content),
                    request=resp.request,
                )

        raise FetchRejected(f"redirect limit exceeded ({MAX_REDIRECTS})")

    @staticmethod
    def _empty_response(resp: httpx.Response) -> httpx.Response:
        return httpx.Response(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=b"",
            request=resp.request,
        )

    async def get(
        self,
        client: httpx.AsyncClient,
        url: str,
        redirect_validator: Optional[Callable[[str], bool]] = None,
    ) -> httpx.Response:
        await asyncio.sleep(_RANDOM.uniform(self.min_delay_s, self.max_delay_s))

        last_exc = None
        for _ in range(self.retries + 1):
            proxy_url = self.proxy_pool.pick() if self.proxy_pool and self.proxy_pool.has_proxies() else None

            try:
                request_kwargs = {"headers": self._headers()}
                if proxy_url:
                    # httpx 0.28 configures proxies at client construction time.
                    async with httpx.AsyncClient(
                        proxy=proxy_url,
                        trust_env=False,
                    ) as proxy_client:
                        resp = await self._bounded_get(
                            proxy_client, url, request_kwargs, redirect_validator
                        )
                else:
                    resp = await self._bounded_get(
                        client, url, request_kwargs, redirect_validator
                    )
                if self.proxy_pool:
                    self.proxy_pool.mark_ok(proxy_url)
                return resp
            except FetchRejected:
                # Policy failures are deterministic; retries only add traffic.
                raise
            except Exception as e:
                last_exc = e
                if self.proxy_pool:
                    self.proxy_pool.mark_fail(proxy_url)
                await asyncio.sleep(0.25 + _RANDOM.uniform(0.1, 0.4))

        raise last_exc
