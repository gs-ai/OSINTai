"""Request hygiene for the harvester's own outbound traffic.

Scope note: this module normalises requests so a harvest run looks like an
ordinary browser session and paces itself politely against a source. It
deliberately does *not* weaken TLS. ``build_ssl_context`` only varies the
*ordering* of strong cipher suites; it never lowers the minimum protocol
version and never disables certificate verification.
"""

import asyncio
import secrets
import ssl
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import ELITE, ANONYMITY_RANK

_RANDOM = secrets.SystemRandom()

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
]

# TLS 1.2 suites only; TLS 1.3 suite selection is not configurable through
# ``set_ciphers`` and is left to OpenSSL. Every entry here is a forward-secret
# AEAD suite -- shuffling the order changes the ClientHello ordering without
# admitting a single weak algorithm.
_STRONG_TLS12_SUITES = [
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
]


def _accept_language() -> str:
    return _RANDOM.choice(
        ["en-US,en;q=0.9", "en-US,en;q=0.8", "en-GB,en-US;q=0.9,en;q=0.8"]
    )


def _is_chromium(user_agent: str) -> bool:
    return "Chrome/" in user_agent or "Edg/" in user_agent


@dataclass
class StealthConfig:
    """Operator-controlled knobs for outbound request shaping."""

    user_agents: List[str] = field(default_factory=lambda: list(DEFAULT_USER_AGENTS))
    min_delay_s: float = 1.5
    max_delay_s: float = 4.5
    randomize_tls_order: bool = True
    # Chaining harvested proxies back into the harvester is OFF by default.
    # See docs/PROXY_HARVESTER.md, "Feedback loop risk".
    allow_chaining: bool = False
    chain_min_anonymity: str = ELITE
    chain_max_age_s: float = 900.0

    def __post_init__(self):
        if not self.user_agents:
            self.user_agents = list(DEFAULT_USER_AGENTS)
        if self.min_delay_s < 0:
            self.min_delay_s = 0.0
        if self.max_delay_s < self.min_delay_s:
            self.max_delay_s = self.min_delay_s


class StealthRotator:
    """Supplies headers, jitter, TLS contexts and (optionally) a chained proxy.

    The chained-proxy path is fed by the validated working set W, but only when
    the operator explicitly enables it. ``set_working_pool`` is how cycle.py
    closes that feedback loop.
    """

    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self._pool: List[Dict] = []
        self._chain_warned = False

    # ---- headers -------------------------------------------------------
    def user_agent(self) -> str:
        return _RANDOM.choice(self.config.user_agents)

    def headers(self, user_agent: Optional[str] = None) -> Dict[str, str]:
        """Build a coherent header set. Header *consistency* matters more than
        header novelty: a Chrome UA paired with Firefox-only Accept values is a
        louder signal than no rotation at all."""
        ua = user_agent or self.user_agent()
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": _accept_language(),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if _is_chromium(ua):
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none"
            headers["Sec-Fetch-User"] = "?1"
        return headers

    def json_headers(self) -> Dict[str, str]:
        headers = self.headers()
        headers["Accept"] = "application/json,text/plain;q=0.9,*/*;q=0.8"
        headers.pop("Upgrade-Insecure-Requests", None)
        headers.pop("Sec-Fetch-User", None)
        return headers

    # ---- pacing --------------------------------------------------------
    def delay_s(self) -> float:
        return _RANDOM.uniform(self.config.min_delay_s, self.config.max_delay_s)

    async def sleep(self) -> float:
        seconds = self.delay_s()
        await asyncio.sleep(seconds)
        return seconds

    # ---- TLS -----------------------------------------------------------
    def build_ssl_context(self) -> ssl.SSLContext:
        """A verifying TLS context with (optionally) shuffled strong suites."""
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if self.config.randomize_tls_order:
            suites = list(_STRONG_TLS12_SUITES)
            _RANDOM.shuffle(suites)
            try:
                context.set_ciphers(":".join(suites))
            except ssl.SSLError:
                # A platform OpenSSL build without one of these suites is not a
                # reason to fail the run; fall back to the verified default.
                context = ssl.create_default_context()
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    # ---- chaining ------------------------------------------------------
    def set_working_pool(self, rows: List[Dict]) -> None:
        """Accept the current working set for use as harvester egress."""
        self._pool = list(rows or [])

    def chained_proxy(self) -> Optional[str]:
        """Return a proxy URL for the harvester's own request, or None.

        Returns None unless chaining is explicitly enabled. Even when enabled,
        only recent, high-anonymity entries qualify: a stale or transparent
        proxy leaks the harvester rather than protecting it.
        """
        if not self.config.allow_chaining:
            return None
        if not self._chain_warned:
            print(
                "[WARN] proxy chaining is enabled: harvest traffic will egress "
                "through unvetted third-party proxies. Treat every fetched "
                "source body as untrusted and assume TLS-terminating middleboxes."
            )
            self._chain_warned = True
        floor = ANONYMITY_RANK.get(self.config.chain_min_anonymity, ANONYMITY_RANK[ELITE])
        now = time.time()
        eligible = [
            row
            for row in self._pool
            if ANONYMITY_RANK.get(row.get("anonymity", ""), 0) >= floor
            and (now - float(row.get("last_ok_epoch") or 0)) <= self.config.chain_max_age_s
            and row.get("protocol") in {"http", "https"}
        ]
        if not eligible:
            return None
        chosen = _RANDOM.choice(eligible)
        return f"http://{chosen['ip']}:{chosen['port']}"
