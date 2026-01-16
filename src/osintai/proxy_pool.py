import random
import time
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class ProxyEntry:
    url: str
    ok: int = 0
    fail: int = 0
    last_used: float = 0.0
    last_fail: float = 0.0

    @property
    def score(self) -> float:
        # Higher is better
        return (self.ok + 1) / (self.fail + 1)

def _normalize_proxy(proxy: str) -> Optional[str]:
    """Normalize proxy URL format."""
    proxy = proxy.strip()
    if not proxy:
        return None
    if not proxy.startswith("http"):
        proxy = "http://" + proxy
    return proxy

class ProxyPool:
    def __init__(self, proxies: List[str]):
        entries = []
        for p in proxies:
            p2 = _normalize_proxy(p)
            if p2:
                entries.append(ProxyEntry(url=p2))
        self.entries: List[ProxyEntry] = entries

    def has_proxies(self) -> bool:
        return len(self.entries) > 0

    def pick(self) -> Optional[str]:
        if not self.entries:
            return None
        # Weighted by score, but also random
        entries = sorted(self.entries, key=lambda e: e.score, reverse=True)
        top = entries[: max(3, len(entries) // 5)]
        chosen = random.choice(top)
        chosen.last_used = time.time()
        return chosen.url

    def mark_ok(self, proxy_url: Optional[str]) -> None:
        if not proxy_url:
            return
        for e in self.entries:
            if e.url == proxy_url:
                e.ok += 1
                return

    def mark_fail(self, proxy_url: Optional[str]) -> None:
        if not proxy_url:
            return
        for e in self.entries:
            if e.url == proxy_url:
                e.fail += 1
                e.last_fail = time.time()
                return

    def as_dict(self) -> List[Dict]:
        return [vars(e) for e in self.entries]
