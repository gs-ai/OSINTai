"""Source fetching and language dispatch.

Two fetch paths exist:

* ``python`` -- httpx GET, used for raw text and JSON endpoints. This is the
  cheap path and the default; the built-in source set is deliberately raw
  endpoints so this path handles all of it.
* ``js`` -- Playwright, used only when a source renders its table client-side.
  Playwright is an optional dependency; the harvester degrades to the static
  path (and says so) when it is absent.

Robots handling is on by default for HTML sources. Raw file endpoints on code
hosts are exempted only when the operator sets ``respect_robots: false`` on that
source, which is a recorded, deliberate choice.
"""

import time
import urllib.robotparser
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx

from .models import ProxyCandidate
from .parsers import dedupe, parse_body
from .sources import (
    KIND_AUTO,
    KIND_HTML,
    RENDER_JS,
    RENDER_PYTHON,
    Source,
    detect_kind,
    select_language,
)
from .stealth import StealthRotator

MAX_SOURCE_BYTES = 8_000_000


@dataclass
class HarvestResult:
    """What one source yielded on one cycle."""

    source_id: str
    ok: bool = False
    renderer: str = RENDER_PYTHON
    kind: str = KIND_AUTO
    status: Optional[int] = None
    candidates: List[ProxyCandidate] = field(default_factory=list)
    bytes_read: int = 0
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    skipped_reason: Optional[str] = None


class RobotsCache:
    """Per-host robots.txt cache with a fail-open-on-error policy.

    Fail-open matches the convention that an unreachable robots.txt does not
    imply a blanket disallow. A robots.txt that is fetched and *does* disallow
    the path is honoured.
    """

    def __init__(self, ttl_s: float = 3600.0):
        self.ttl_s = ttl_s
        self._cache: Dict[str, Tuple[float, Optional[urllib.robotparser.RobotFileParser]]] = {}

    async def allowed(self, client: httpx.AsyncClient, url: str, user_agent: str) -> bool:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        now = time.time()
        cached = self._cache.get(origin)
        if cached and (now - cached[0]) < self.ttl_s:
            parser = cached[1]
        else:
            parser = await self._fetch(client, origin)
            self._cache[origin] = (now, parser)
        if parser is None:
            return True
        return parser.can_fetch(user_agent, url)

    async def _fetch(
        self, client: httpx.AsyncClient, origin: str
    ) -> Optional[urllib.robotparser.RobotFileParser]:
        try:
            response = await client.get(urljoin(origin, "/robots.txt"), timeout=10.0)
        except (httpx.HTTPError, OSError):
            return None
        if response.status_code != 200:
            return None
        parser = urllib.robotparser.RobotFileParser()
        parser.parse(response.text.splitlines())
        return parser


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


async def fetch_static(
    client: httpx.AsyncClient,
    source: Source,
    rotator: StealthRotator,
    timeout_s: float = 30.0,
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """GET a source over httpx. Returns (body, status, content_type, error)."""
    headers = rotator.json_headers() if source.kind == "json" else rotator.headers()
    try:
        async with client.stream(
            "GET", source.url, headers=headers, timeout=timeout_s, follow_redirects=True
        ) as response:
            status = response.status_code
            content_type = response.headers.get("content-type", "")
            if status != 200:
                return None, status, content_type, f"http {status}"
            buffer = bytearray()
            async for chunk in response.aiter_bytes():
                buffer.extend(chunk)
                if len(buffer) > MAX_SOURCE_BYTES:
                    return (
                        None,
                        status,
                        content_type,
                        f"source exceeded {MAX_SOURCE_BYTES} byte limit",
                    )
            return buffer.decode("utf-8", errors="replace"), status, content_type, None
    except httpx.TimeoutException:
        return None, None, None, "timeout"
    except (httpx.HTTPError, OSError) as exc:
        return None, None, None, f"{type(exc).__name__}: {exc}"[:160]


async def fetch_rendered(
    source: Source, rotator: StealthRotator, timeout_s: float = 45.0
) -> Tuple[Optional[str], Optional[str]]:
    """Render a JS-driven source with Playwright. Returns (html, error)."""
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return None, "playwright not installed (pip install -r requirements-proxyharvest.txt)"

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            try:
                context = await browser.new_context(
                    user_agent=rotator.user_agent(),
                    locale="en-US",
                    viewport={"width": 1366, "height": 900},
                )
                page = await context.new_page()
                await page.goto(source.url, timeout=timeout_s * 1000, wait_until="networkidle")
                html = await page.content()
                await context.close()
                return html, None
            finally:
                await browser.close()
    except Exception as exc:  # Playwright raises a wide surface of driver errors.
        return None, f"render failed: {type(exc).__name__}: {exc}"[:200]


async def harvest_source(
    client: httpx.AsyncClient,
    source: Source,
    rotator: StealthRotator,
    robots: Optional[RobotsCache] = None,
    allow_js: bool = False,
    timeout_s: float = 30.0,
) -> HarvestResult:
    """Fetch and parse one source, applying the L(s) language heuristic."""
    result = HarvestResult(source_id=source.id)
    started = time.perf_counter()

    user_agent = rotator.user_agent()
    if source.respect_robots and robots is not None:
        if not await robots.allowed(client, source.url, user_agent):
            result.skipped_reason = "disallowed by robots.txt"
            result.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return result

    renderer = select_language(source)
    body: Optional[str] = None

    if renderer == RENDER_PYTHON:
        body, status, content_type, error = await fetch_static(client, source, rotator, timeout_s)
        result.status = status
        if error:
            result.error = error
            result.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return result

        # Escalate to the rendered path only when the static body proves it is
        # needed: an SPA shell with no endpoints in it.
        if source.renderer == "auto" and source.kind in {KIND_AUTO, KIND_HTML}:
            escalated = select_language(source, body)
            if escalated == RENDER_JS:
                if allow_js:
                    rendered, render_error = await fetch_rendered(source, rotator)
                    if rendered:
                        body, renderer = rendered, RENDER_JS
                    else:
                        result.error = render_error
                else:
                    result.error = (
                        "source needs JS rendering; re-run with --enable-js "
                        "(requires playwright)"
                    )
        kind = detect_kind(content_type or "", body or "")
    else:
        if not allow_js:
            result.skipped_reason = "renderer=js but --enable-js not set"
            result.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return result
        body, render_error = await fetch_rendered(source, rotator)
        if render_error:
            result.error = render_error
            result.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return result
        kind = KIND_HTML

    result.renderer = renderer
    result.kind = source.kind if source.kind != KIND_AUTO else kind
    if not body:
        result.error = result.error or "empty body"
        result.elapsed_ms = (time.perf_counter() - started) * 1000.0
        return result

    result.bytes_read = len(body)
    result.candidates = dedupe(parse_body(result.kind, body, source.id, source.protocol))
    result.ok = True
    result.elapsed_ms = (time.perf_counter() - started) * 1000.0
    return result


async def harvest_all(
    sources: List[Source],
    rotator: StealthRotator,
    allow_js: bool = False,
    respect_robots: bool = True,
    timeout_s: float = 30.0,
    verify=True,
    progress=None,
) -> List[HarvestResult]:
    """Fetch every enabled source sequentially, with jitter between requests.

    Sequential-with-jitter is deliberate: a handful of GETs per cycle against
    public lists does not need concurrency, and pacing keeps the run well inside
    what those endpoints expect.
    """
    robots = RobotsCache() if respect_robots else None
    results: List[HarvestResult] = []

    proxy = rotator.chained_proxy()
    client_kwargs = {
        "timeout": httpx.Timeout(timeout_s, connect=10.0),
        "verify": verify,
        "follow_redirects": True,
        "trust_env": proxy is None,
    }
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        for index, source in enumerate(sources):
            if index:
                await rotator.sleep()
            result = await harvest_source(
                client, source, rotator, robots, allow_js, timeout_s
            )
            results.append(result)
            if progress:
                progress(index + 1, len(sources), result)
    return results


def merge_candidates(results: List[HarvestResult]) -> List[ProxyCandidate]:
    """Flatten and de-duplicate every source's candidates for this cycle."""
    merged: List[ProxyCandidate] = []
    for result in results:
        merged.extend(result.candidates)
    return dedupe(merged)
