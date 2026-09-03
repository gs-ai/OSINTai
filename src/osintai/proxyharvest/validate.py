"""Concurrent proxy validation with anonymity grading and integrity checking.

A candidate joins the working set W only if it: answers within the latency
budget, returns a body that matches the echo endpoint's expected JSON shape
(catching content injection and captive-portal interception), requires no
authentication, and -- when two-phase confirmation is on -- repeats that
behaviour on a second probe after a short delay. The second probe is what
separates a usable proxy from one that answers once and dies.
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import httpx

from .models import (
    ANONYMOUS,
    ANONYMITY_RANK,
    ELITE,
    ProxyCandidate,
    TRANSPARENT,
    UNKNOWN_ANON,
    ValidationResult,
)

# Header names that reveal a proxy hop is present at all.
_PROXY_HEADERS = (
    "via",
    "x-forwarded-for",
    "x-forwarded",
    "forwarded",
    "forwarded-for",
    "x-real-ip",
    "proxy-connection",
    "x-proxy-id",
    "client-ip",
    "x-client-ip",
)

DEFAULT_ECHO_URLS = (
    "https://httpbin.org/get",
    "https://postman-echo.com/get",
)


def _socks_available() -> bool:
    try:
        import socksio  # noqa: F401
        return True
    except ImportError:
        return False


SOCKS_AVAILABLE = _socks_available()


@dataclass
class ValidationConfig:
    """Probe budget and acceptance thresholds."""

    echo_urls: Tuple[str, ...] = DEFAULT_ECHO_URLS
    timeout_s: float = 8.0
    connect_timeout_s: float = 5.0
    max_latency_ms: float = 6000.0
    concurrency: int = 60
    min_anonymity: str = ANONYMOUS
    confirm: bool = True
    confirm_delay_s: float = 2.0
    max_body_bytes: int = 64_000
    verify_tls: bool = True

    def __post_init__(self):
        if self.concurrency < 1:
            self.concurrency = 1
        if self.min_anonymity not in ANONYMITY_RANK:
            raise ValueError(f"unknown anonymity grade: {self.min_anonymity}")
        if not self.echo_urls:
            self.echo_urls = DEFAULT_ECHO_URLS


@dataclass
class ValidationReport:
    """Aggregate outcome of one validation pass."""

    attempted: int = 0
    passed: List[ValidationResult] = field(default_factory=list)
    failed: List[ValidationResult] = field(default_factory=list)
    skipped: List[ValidationResult] = field(default_factory=list)

    @property
    def yield_rate(self) -> float:
        return (len(self.passed) / self.attempted) if self.attempted else 0.0


def proxy_url(candidate: ProxyCandidate) -> str:
    """Build the transport URL. No credential fields are ever emitted."""
    if candidate.protocol in {"socks4", "socks5"}:
        return f"{candidate.protocol}://{candidate.ip}:{candidate.port}"
    return f"http://{candidate.ip}:{candidate.port}"


def parse_echo(body: str) -> Optional[Dict]:
    """Parse an echo response, returning None if it is not the expected shape.

    A body that is not JSON, or that lacks both ``headers`` and ``origin``, means
    something between here and the endpoint rewrote the response. That is a hard
    fail, not a soft one.
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if "headers" not in data and "origin" not in data and "ip" not in data:
        return None
    return data


def grade_anonymity(echo: Dict, local_ip: Optional[str]) -> Tuple[str, Optional[str]]:
    """Grade the hop and extract the exit IP.

    transparent -- our own address is disclosed (via origin or a forwarding header)
    anonymous   -- a proxy is disclosed, but our address is not
    elite       -- no proxy disclosure and no leak of our address
    """
    headers = {str(k).lower(): str(v) for k, v in (echo.get("headers") or {}).items()}
    origin = str(echo.get("origin") or echo.get("ip") or "").strip()
    exit_ip = origin.split(",")[0].strip() or None

    leaked = False
    if local_ip:
        if local_ip in origin:
            leaked = True
        else:
            for name in _PROXY_HEADERS:
                if local_ip in headers.get(name, ""):
                    leaked = True
                    break

    if leaked:
        return TRANSPARENT, exit_ip

    disclosed = any(name in headers for name in _PROXY_HEADERS)
    if "," in origin:
        # A comma-joined origin is itself a forwarding chain disclosure.
        disclosed = True

    if disclosed:
        return ANONYMOUS, exit_ip
    if not exit_ip:
        return UNKNOWN_ANON, exit_ip
    return ELITE, exit_ip


async def _read_bounded(response: httpx.Response, limit: int) -> str:
    buffer = bytearray()
    async for chunk in response.aiter_bytes():
        buffer.extend(chunk)
        if len(buffer) > limit:
            break
    return buffer[:limit].decode("utf-8", errors="replace")


async def detect_local_ip(
    config: ValidationConfig, verify=True, transport=None
) -> Optional[str]:
    """Fetch our own egress address directly, so leaks are detectable.

    Without this the transparent grade cannot be assigned reliably: a proxy that
    forwards our real address would otherwise be scored 'anonymous'.
    """
    timeout = httpx.Timeout(config.timeout_s, connect=config.connect_timeout_s)
    for url in config.echo_urls:
        try:
            client_kwargs = {"timeout": timeout, "trust_env": True}
            if transport is None:
                client_kwargs["verify"] = verify
            else:
                client_kwargs["transport"] = transport
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    continue
                echo = parse_echo(response.text[: config.max_body_bytes])
                if not echo:
                    continue
                origin = str(echo.get("origin") or echo.get("ip") or "")
                candidate_ip = origin.split(",")[0].strip()
                if candidate_ip:
                    return candidate_ip
        except (httpx.HTTPError, OSError):
            continue
    return None


async def probe(
    candidate: ProxyCandidate,
    config: ValidationConfig,
    local_ip: Optional[str],
    echo_url: Optional[str] = None,
    verify=True,
    transport=None,
) -> ValidationResult:
    """Run one probe against one candidate.

    ``transport`` exists so the probe path can be exercised against an
    httpx.MockTransport in tests without opening a socket.
    """
    result = ValidationResult(candidate=candidate)

    if candidate.protocol in {"socks4", "socks5"} and not SOCKS_AVAILABLE:
        result.error = "socks support unavailable (pip install httpx[socks])"
        return result

    url = echo_url or config.echo_urls[0]
    timeout = httpx.Timeout(config.timeout_s, connect=config.connect_timeout_s)
    client_kwargs = {
        "timeout": timeout,
        "follow_redirects": False,
        "trust_env": False,
    }
    if transport is None:
        client_kwargs["proxy"] = proxy_url(candidate)
        client_kwargs["verify"] = verify
    else:
        client_kwargs["transport"] = transport

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(**client_kwargs) as client:
            async with client.stream("GET", url) as response:
                if response.status_code == 407:
                    result.error = "proxy authentication required (excluded: no-auth constraint)"
                    return result
                if response.status_code != 200:
                    result.error = f"http {response.status_code}"
                    return result
                body = await _read_bounded(response, config.max_body_bytes)
    except httpx.ProxyError as exc:
        result.error = f"proxy error: {type(exc).__name__}"
        return result
    except httpx.TimeoutException:
        result.error = "timeout"
        return result
    except (httpx.HTTPError, OSError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"[:160]
        return result

    result.latency_ms = (time.perf_counter() - started) * 1000.0

    echo = parse_echo(body)
    if echo is None:
        # Answered, but not with the endpoint's payload: interception or an
        # injected interstitial. Never admit these to W.
        result.error = "response body did not match echo schema (possible interception)"
        return result
    result.body_intact = True

    if result.latency_ms > config.max_latency_ms:
        result.error = f"latency {result.latency_ms:.0f}ms over budget {config.max_latency_ms:.0f}ms"
        return result

    result.anonymity, result.exit_ip = grade_anonymity(echo, local_ip)
    if ANONYMITY_RANK[result.anonymity] < ANONYMITY_RANK[config.min_anonymity]:
        result.error = f"anonymity {result.anonymity} below required {config.min_anonymity}"
        return result

    result.ok = True
    return result


async def validate_all(
    candidates: Sequence[ProxyCandidate],
    config: Optional[ValidationConfig] = None,
    local_ip: Optional[str] = None,
    progress=None,
    transport=None,
) -> ValidationReport:
    """Validate a candidate set concurrently, with optional confirmation pass."""
    config = config or ValidationConfig()
    report = ValidationReport(attempted=len(candidates))
    if not candidates:
        return report

    semaphore = asyncio.Semaphore(config.concurrency)
    done = 0
    lock = asyncio.Lock()

    async def run_one(candidate: ProxyCandidate) -> ValidationResult:
        nonlocal done
        async with semaphore:
            result = await probe(
                candidate, config, local_ip, verify=config.verify_tls, transport=transport
            )
        async with lock:
            done += 1
            if progress:
                progress(done, len(candidates))
        return result

    first_pass = await asyncio.gather(*(run_one(c) for c in candidates))

    survivors = [r for r in first_pass if r.ok]
    for result in first_pass:
        if not result.ok:
            if result.error and "socks support unavailable" in result.error:
                report.skipped.append(result)
            else:
                report.failed.append(result)

    if not config.confirm:
        for result in survivors:
            result.confirmed = False
        report.passed.extend(survivors)
        return report

    # Second pass against a different echo endpoint where one is configured, so
    # a proxy that has simply cached one response cannot fake a confirmation.
    await asyncio.sleep(config.confirm_delay_s)
    confirm_url = config.echo_urls[1] if len(config.echo_urls) > 1 else config.echo_urls[0]

    async def confirm_one(result: ValidationResult) -> ValidationResult:
        async with semaphore:
            second = await probe(
                result.candidate, config, local_ip, echo_url=confirm_url,
                verify=config.verify_tls, transport=transport,
            )
        if second.ok:
            result.confirmed = True
            # Keep the slower of the two measurements: it is the honest one to
            # plan against.
            result.latency_ms = max(result.latency_ms or 0.0, second.latency_ms or 0.0)
            # Anonymity can differ per endpoint; keep the weaker grade.
            if ANONYMITY_RANK[second.anonymity] < ANONYMITY_RANK[result.anonymity]:
                result.anonymity = second.anonymity
            return result
        result.ok = False
        result.confirmed = False
        result.error = f"failed confirmation probe: {second.error}"
        return result

    confirmed = await asyncio.gather(*(confirm_one(r) for r in survivors))
    for result in confirmed:
        if result.ok and ANONYMITY_RANK[result.anonymity] >= ANONYMITY_RANK[config.min_anonymity]:
            report.passed.append(result)
        else:
            report.failed.append(result)
    return report
