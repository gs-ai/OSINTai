"""Candidate extraction from raw text, JSON, and HTML source bodies."""

import json
import re
from typing import Iterable, List, Optional, Sequence
from urllib.parse import urlparse

from .models import ProxyCandidate, SUPPORTED_PROTOCOLS, is_routable_public_ip

# ip:port, ip|port and "scheme://ip:port" all appear across public lists.
_ENDPOINT_RE = re.compile(
    r"(?:(?P<scheme>https?|socks[45])://)?"
    r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})"
    r"\s*[:|]\s*"
    r"(?P<port>\d{2,5})"
)

_PROTOCOL_ALIASES = {
    "http": "http",
    "https": "https",
    "socks4": "socks4",
    "socks5": "socks5",
    "socks4a": "socks4",
    "socks5h": "socks5",
}

# Field names observed across public JSON proxy feeds.
_IP_KEYS = ("ip", "host", "addr", "address", "proxy_ip", "ipAddress")
_PORT_KEYS = ("port", "proxy_port")
_PROTOCOL_KEYS = ("protocol", "proto", "type", "scheme", "protocols")


def normalize_protocol(value: Optional[str], default: str = "http") -> str:
    if not value:
        return default
    token = str(value).strip().lower()
    return _PROTOCOL_ALIASES.get(token, default)


def _make(ip: str, port, protocol: str, source_id: str) -> Optional[ProxyCandidate]:
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return None
    if not is_routable_public_ip(ip) or not 1 <= port_int <= 65535:
        return None
    if protocol not in SUPPORTED_PROTOCOLS:
        return None
    return ProxyCandidate(ip=ip, port=port_int, protocol=protocol, source_id=source_id)


def parse_text(body: str, source_id: str = "", default_protocol: str = "http") -> List[ProxyCandidate]:
    """Extract candidates from a raw text list.

    Handles bare ``ip:port``, ``ip|port``, and scheme-prefixed entries. A scheme
    found inline overrides the source's declared default protocol.
    """
    found: List[ProxyCandidate] = []
    for line in (body or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENDPOINT_RE.search(line)
        if not match:
            continue
        protocol = normalize_protocol(match.group("scheme"), default_protocol)
        candidate = _make(match.group("ip"), match.group("port"), protocol, source_id)
        if candidate:
            found.append(candidate)
    return found


def _protocol_from_value(value, default: str) -> str:
    """Resolve a JSON protocol field that may be a string, list, or URL."""
    if isinstance(value, (list, tuple)) and value:
        value = value[0]
    if isinstance(value, str) and "://" in value:
        value = urlparse(value).scheme
    return normalize_protocol(value if isinstance(value, str) else None, default)


def _walk_json(node, source_id: str, default_protocol: str, out: List[ProxyCandidate]) -> None:
    if isinstance(node, list):
        for item in node:
            _walk_json(item, source_id, default_protocol, out)
        return
    if not isinstance(node, dict):
        return

    ip = next((node[k] for k in _IP_KEYS if isinstance(node.get(k), str)), None)
    port = next((node[k] for k in _PORT_KEYS if node.get(k) is not None), None)

    if ip and ":" in ip and port is None:
        # Some feeds pack "ip:port" into a single field.
        host, _, packed_port = ip.rpartition(":")
        ip, port = host, packed_port

    if ip and port is not None:
        raw_protocol = next((node[k] for k in _PROTOCOL_KEYS if node.get(k)), None)
        protocol = _protocol_from_value(raw_protocol, default_protocol)
        candidate = _make(ip, port, protocol, source_id)
        if candidate:
            out.append(candidate)

    for value in node.values():
        if isinstance(value, (list, dict)):
            _walk_json(value, source_id, default_protocol, out)


def parse_json(body: str, source_id: str = "", default_protocol: str = "http") -> List[ProxyCandidate]:
    """Extract candidates from a JSON or JSON-lines feed."""
    out: List[ProxyCandidate] = []
    text = (body or "").strip()
    if not text:
        return out
    try:
        _walk_json(json.loads(text), source_id, default_protocol, out)
        return out
    except (json.JSONDecodeError, TypeError):
        pass

    # Fall back to JSON-lines before giving up on the structured path.
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            _walk_json(json.loads(line), source_id, default_protocol, out)
        except (json.JSONDecodeError, TypeError):
            continue
    return out


def parse_html(body: str, source_id: str = "", default_protocol: str = "http") -> List[ProxyCandidate]:
    """Extract candidates from an HTML table.

    Tries a real parse first so column semantics survive; falls back to a regex
    sweep of the visible text when the markup is not table-shaped.
    """
    if not body:
        return []
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return parse_text(body, source_id, default_protocol)

    soup = BeautifulSoup(body, "lxml") if _has_lxml() else BeautifulSoup(body, "html.parser")
    found: List[ProxyCandidate] = []

    for row in soup.find_all("tr"):
        cells = [cell.get_text(strip=True) for cell in row.find_all(["td", "th"])]
        if len(cells) < 2:
            continue
        ip = cells[0]
        port = cells[1]
        if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", ip) or not port.isdigit():
            continue
        protocol = default_protocol
        for cell in cells[2:]:
            token = cell.strip().lower()
            if token in _PROTOCOL_ALIASES:
                protocol = _PROTOCOL_ALIASES[token]
                break
        candidate = _make(ip, port, protocol, source_id)
        if candidate:
            found.append(candidate)

    if found:
        return found
    return parse_text(soup.get_text("\n"), source_id, default_protocol)


def _has_lxml() -> bool:
    try:
        import lxml  # noqa: F401
        return True
    except ImportError:
        return False


def dedupe(candidates: Iterable[ProxyCandidate]) -> List[ProxyCandidate]:
    """Ordered de-duplication on (protocol, ip, port)."""
    seen = set()
    out: List[ProxyCandidate] = []
    for candidate in candidates:
        if candidate.key in seen:
            continue
        seen.add(candidate.key)
        out.append(candidate)
    return out


def parse_body(kind: str, body: str, source_id: str = "", default_protocol: str = "http") -> List[ProxyCandidate]:
    """Dispatch to the parser matching the resolved source kind."""
    if kind == "json":
        return parse_json(body, source_id, default_protocol)
    if kind == "html":
        return parse_html(body, source_id, default_protocol)
    return parse_text(body, source_id, default_protocol)


def candidates_from_lines(lines: Sequence[str], source_id: str = "file") -> List[ProxyCandidate]:
    return dedupe(parse_text("\n".join(lines), source_id))
