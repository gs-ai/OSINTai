"""Core record types for the proxy harvest / validation pipeline.

Naming discipline: nothing in this module ever asserts that an address *is*
residential. Classification is evidence-graded and the vocabulary reflects that
(``residential_indicated`` rather than ``residential``). See classify.py.
"""

import ipaddress
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

# Anonymity grades, ordered weakest to strongest.
TRANSPARENT = "transparent"
ANONYMOUS = "anonymous"
ELITE = "elite"
UNKNOWN_ANON = "unknown"

ANONYMITY_RANK = {
    UNKNOWN_ANON: 0,
    TRANSPARENT: 1,
    ANONYMOUS: 2,
    ELITE: 3,
}

# Network classification vocabulary. "_indicated" suffixes are deliberate: these
# are heuristic reads of ASN/PTR evidence, not verified subscriber-line facts.
RESIDENTIAL_INDICATED = "residential_indicated"
MOBILE_INDICATED = "mobile_indicated"
DATACENTER = "datacenter"
HOSTING = "hosting"
UNKNOWN_CLASS = "unknown"

SUPPORTED_PROTOCOLS = ("http", "https", "socks4", "socks5")


def is_routable_public_ip(value: str) -> bool:
    """Reject loopback, private, link-local, reserved and multicast addresses."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


@dataclass(frozen=True)
class ProxyCandidate:
    """An unvalidated (ip, port, protocol) triple as parsed from a source."""

    ip: str
    port: int
    protocol: str = "http"
    source_id: str = ""

    @property
    def key(self) -> str:
        return f"{self.protocol}://{self.ip}:{self.port}"

    @property
    def endpoint(self) -> str:
        return f"{self.ip}:{self.port}"

    def is_valid(self) -> bool:
        return (
            is_routable_public_ip(self.ip)
            and 1 <= self.port <= 65535
            and self.protocol in SUPPORTED_PROTOCOLS
        )


@dataclass
class ValidationResult:
    """Outcome of one probe against a candidate."""

    candidate: ProxyCandidate
    ok: bool = False
    latency_ms: Optional[float] = None
    anonymity: str = UNKNOWN_ANON
    exit_ip: Optional[str] = None
    error: Optional[str] = None
    body_intact: bool = False
    confirmed: bool = False
    checked_at: float = field(default_factory=time.time)

    def to_row(self) -> Dict:
        row = asdict(self)
        row.pop("candidate", None)
        row["key"] = self.candidate.key
        return row


@dataclass
class Classification:
    """Evidence-graded network classification for an exit address."""

    network_class: str = UNKNOWN_CLASS
    asn: Optional[int] = None
    as_org: Optional[str] = None
    country: Optional[str] = None
    ptr: Optional[str] = None
    basis: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_row(self) -> Dict:
        return asdict(self)


@dataclass
class WorkingProxy:
    """A validated member of the working set W."""

    candidate: ProxyCandidate
    latency_ms: float
    anonymity: str
    exit_ip: Optional[str]
    classification: Classification
    first_seen: float
    last_ok: float
    ok_count: int = 1
    fail_count: int = 0

    @property
    def key(self) -> str:
        return self.candidate.key

    def to_row(self) -> Dict:
        return {
            "key": self.key,
            "ip": self.candidate.ip,
            "port": self.candidate.port,
            "protocol": self.candidate.protocol,
            "source_id": self.candidate.source_id,
            "latency_ms": round(self.latency_ms, 1),
            "anonymity": self.anonymity,
            "exit_ip": self.exit_ip,
            "network_class": self.classification.network_class,
            "classification_confidence": round(self.classification.confidence, 2),
            "classification_basis": "; ".join(self.classification.basis),
            "asn": self.classification.asn,
            "as_org": self.classification.as_org,
            "country": self.classification.country,
            "ptr": self.classification.ptr,
            "first_seen": first_seen_iso(self.first_seen),
            "last_ok": first_seen_iso(self.last_ok),
            "ok_count": self.ok_count,
            "fail_count": self.fail_count,
        }


def first_seen_iso(epoch: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
