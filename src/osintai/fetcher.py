import random
import asyncio
import httpx
from typing import Optional, Dict
from .proxy_pool import ProxyPool

class AsyncFetcher:
    def __init__(
        self,
        user_agents,
        proxy_pool: Optional[ProxyPool] = None,
        timeout_s: float = 20.0,
        min_delay_s: float = 0.2,
        max_delay_s: float = 1.2,
        retries: int = 2
    ):
        self.user_agents = user_agents or ["Mozilla/5.0"]
        self.proxy_pool = proxy_pool
        self.timeout_s = timeout_s
        self.min_delay_s = min_delay_s
        self.max_delay_s = max_delay_s
        self.retries = retries

    def _headers(self) -> Dict[str, str]:
        ua = random.choice(self.user_agents)
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    async def get(self, client: httpx.AsyncClient, url: str) -> httpx.Response:
        await asyncio.sleep(random.uniform(self.min_delay_s, self.max_delay_s))

        last_exc = None
        for _ in range(self.retries + 1):
            proxy_url = self.proxy_pool.pick() if self.proxy_pool and self.proxy_pool.has_proxies() else None

            # For now, skip proxy support in this test
            try:
                resp = await client.get(
                    url,
                    headers=self._headers(),
                    follow_redirects=True
                )
                return resp
            except Exception as e:
                last_exc = e
                await asyncio.sleep(0.25 + random.uniform(0.1, 0.4))

        raise last_exc
