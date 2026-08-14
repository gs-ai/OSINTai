"""Entity typing, normalization and cross-page identity for OSINTai.

The crawler's Extractor mines a page for indicator strings. This module turns those strings
into typed, normalized entities that can be compared across pages, which is what correlation
and lead generation need.

Identifiers are typed from their shape and normalized before comparison. Phone variants are
kept separately from observed forms so the same number written four ways is one entity
without claiming that an unobserved representation appeared in source material.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# Identifier types
EMAIL = "email"
PHONE = "phone"
NAME = "name"
USERNAME = "username"
DOMAIN = "domain"
IP = "ip"
URL = "url"
CRYPTO_BTC = "btc"
CRYPTO_ETH = "eth"
DATE = "date"
ADDRESS = "address"
SECRET_KIND = "secret"

IDENTIFIER_TYPES = (
    EMAIL, PHONE, NAME, USERNAME, DOMAIN, IP, URL,
    CRYPTO_BTC, CRYPTO_ETH, DATE, ADDRESS, SECRET_KIND,
)

_EMAIL_SHAPE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_PHONE_SHAPE = re.compile(r"^[+\d\s().-]+$")
_NAME_SHAPE = re.compile(r"^[a-z][a-z .'-]+\s+[a-z .'-]+$", re.IGNORECASE)

# Extended indicator classes used after the crawl. Broad path matching is deliberately
# excluded because it would match almost any slash-separated text.
DATE_RE = re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\b")
NAME_CANDIDATE_RE = re.compile(r"\b[A-Z][a-z]{1,20} [A-Z][a-z]{1,20}\b")
ADDRESS_RE = re.compile(
    r"\b\d{1,5} [A-Za-z0-9.\s]{2,40}?"
    r"(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Terrace|Ter)\b"
)
API_TOKEN_RE = re.compile(
    r"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret|token)"
    r"[\"'\s:=]{1,5}[\"']?([A-Za-z0-9_\-]{16,64})[\"']?"
)
JWT_RE = re.compile(r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b")

# The crawler's own domain and handle patterns are ASCII-only, which means a lookalike
# domain built from Cyrillic or fullwidth characters is invisible to it — precisely the
# case homoglyph analysis exists to catch. These patterns accept non-ASCII letters so the
# check has something to inspect. Kept here rather than in Extractor so the crawl hot path
# and its output schema stay exactly as they were.
UNICODE_DOMAIN_RE = re.compile(
    r"(?:[^\W\d_]|[a-zA-Z0-9-])+(?:\.(?:[^\W\d_]|[a-zA-Z0-9-])+)+", re.UNICODE
)
UNICODE_HANDLE_RE = re.compile(r"(?<![\w@])@((?:[^\W]|[_.]){3,30})", re.UNICODE)


def _has_non_ascii(value: str) -> bool:
    return any(ord(ch) > 0x7E for ch in value)
CREDENTIAL_PAIR_RE = re.compile(
    r"(?m)^[ \t]*([\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|[\w.-]{3,32}):(?!//)(\S{6,64})[ \t]*$"
)

# Left-hand values that make a `word:value` line something other than a credential. Without
# these a bare URL on its own line reads as "user https" with a six-character secret.
_NOT_CREDENTIAL_KEYS = {
    "http", "https", "ftp", "ftps", "mailto", "tel", "data", "file", "ws", "wss",
    "note", "notes", "source", "sources", "url", "link", "links", "ref", "see",
    "date", "time", "subject", "from", "to", "cc", "bcc", "re", "via", "id",
    "version", "type", "name", "title", "author", "tags", "category", "status",
}


def detect_type(value: str) -> str:
    """Best-effort identifier typing from shape alone.

    Order matters: an email is unambiguous, a mostly-digit string is a phone, two
    capitalized words are a name, and everything else falls through to username.
    """
    v = (value or "").strip()
    if not v:
        return USERNAME
    if _EMAIL_SHAPE.match(v):
        return EMAIL
    digit_count = sum(1 for ch in v if ch.isdigit())
    if digit_count >= 7 and _PHONE_SHAPE.match(v):
        return PHONE
    if "@" not in v and _NAME_SHAPE.match(v):
        return NAME
    return USERNAME


def normalize_phone(raw: str) -> Dict[str, str]:
    """Reduce a phone string to its digits and E.164-ish form."""
    trimmed = (raw or "").strip()
    has_plus = trimmed.startswith("+")
    digits = "".join(ch for ch in trimmed if ch.isdigit())
    return {
        "digits": digits,
        "e164": f"+{digits}" if has_plus and digits else digits,
        "has_plus": "yes" if has_plus else "no",
    }


def phone_variants(raw: str) -> List[str]:
    """Every common written form of a US-style number, so page-to-page matching works."""
    digits = normalize_phone(raw)["digits"]
    variants: Set[str] = set()
    if (raw or "").strip():
        variants.add(raw.strip())
    if digits:
        variants.add(digits)
    ten = digits[1:] if len(digits) == 11 and digits.startswith("1") else digits
    if len(ten) == 10:
        a, b, c = ten[:3], ten[3:6], ten[6:]
        variants.update({
            f"({a}) {b}-{c}",
            f"{a}-{b}-{c}",
            f"{a}.{b}.{c}",
            f"{a} {b} {c}",
            f"+1{ten}",
            ten,
        })
    return sorted(v for v in variants if v)


def canonical(value: str, kind: str) -> str:
    """The comparison key for an entity of a given kind.

    Two entities are the same entity when their canonical forms match. Everything that is
    case- or punctuation-insensitive gets folded here so correlation does not have to know
    the rules for each type.
    """
    v = (value or "").strip()
    if not v:
        return ""
    if kind in (EMAIL, DOMAIN, USERNAME, CRYPTO_ETH, URL):
        return v.lower().strip(".")
    if kind == PHONE:
        digits = normalize_phone(v)["digits"]
        return digits[1:] if len(digits) == 11 and digits.startswith("1") else digits
    if kind == NAME:
        return " ".join(v.split()).lower()
    return v


@dataclass
class Entity:
    """A typed identifier and every page it was observed on.

    Observations accumulate; they are never merged away. The source list is what later lets
    a correlation say why it thinks two things are related.
    """

    kind: str
    value: str
    canonical_value: str = ""
    sources: List[str] = field(default_factory=list)
    variants: List[str] = field(default_factory=list)
    observed_forms: List[str] = field(default_factory=list)
    count: int = 0

    def __post_init__(self) -> None:
        if not self.canonical_value:
            self.canonical_value = canonical(self.value, self.kind)

    @property
    def key(self) -> Tuple[str, str]:
        return (self.kind, self.canonical_value)

    def observe(self, source: str, raw: str = "") -> None:
        """Record one sighting.

        `observed_forms` holds the literal strings actually seen, which is separate from
        `variants` (forms this identifier *could* be written in). Only the observed list can
        support a claim about how something was written.
        """
        self.count += 1
        if source and source not in self.sources:
            self.sources.append(source)
        raw = (raw or "").strip()
        if raw and raw not in self.observed_forms and len(self.observed_forms) < 12:
            self.observed_forms.append(raw)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "value": self.value,
            "canonical": self.canonical_value,
            "sources": self.sources,
            "source_count": len(self.sources),
            "variants": self.variants,
            "observed_forms": self.observed_forms,
            "count": self.count,
        }


class EntityIndex:
    """All entities seen in a run, keyed by (kind, canonical value)."""

    def __init__(self) -> None:
        self._entities: Dict[Tuple[str, str], Entity] = {}

    def add(self, kind: str, value: str, source: str) -> Optional[Entity]:
        key_value = canonical(value, kind)
        if not key_value:
            return None
        key = (kind, key_value)
        entity = self._entities.get(key)
        if entity is None:
            entity = Entity(kind=kind, value=value, canonical_value=key_value)
            if kind == PHONE:
                entity.variants = phone_variants(value)
            self._entities[key] = entity
        entity.observe(source, raw=value)
        return entity

    def add_many(self, kind: str, values: Iterable[str], source: str) -> None:
        for value in values or []:
            self.add(kind, value, source)

    def get(self, kind: str, value: str) -> Optional[Entity]:
        return self._entities.get((kind, canonical(value, kind)))

    def of_kind(self, kind: str) -> List[Entity]:
        return [e for e in self._entities.values() if e.kind == kind]

    def all(self) -> List[Entity]:
        return list(self._entities.values())

    def multi_source(self, minimum: int = 2) -> List[Entity]:
        """Entities corroborated across several pages — the ones worth attention first."""
        return sorted(
            (e for e in self._entities.values() if len(e.sources) >= minimum),
            key=lambda e: (-len(e.sources), e.kind, e.canonical_value),
        )

    def by_source(self) -> Dict[str, List[Entity]]:
        mapping: Dict[str, List[Entity]] = {}
        for entity in self._entities.values():
            for source in entity.sources:
                mapping.setdefault(source, []).append(entity)
        return mapping

    def __len__(self) -> int:
        return len(self._entities)


# Maps the indicator keys the crawler already writes onto entity kinds. Anything the
# extractor gains later only needs a line here to become correlatable.
INDICATOR_KIND_MAP = {
    "emails": EMAIL,
    "phones": PHONE,
    "domains": DOMAIN,
    "ip_addresses": IP,
    "urls": URL,
    "btc_addresses": CRYPTO_BTC,
    "eth_addresses": CRYPTO_ETH,
    "social_handles": USERNAME,
    "dates": DATE,
    "name_candidates": NAME,
    "addresses": ADDRESS,
}


def index_indicators(rows: Iterable[Dict[str, Any]]) -> EntityIndex:
    """Build an entity index from the indicator records the crawl already produced."""
    index = EntityIndex()
    for row in rows or []:
        source = row.get("url") or ""
        for indicator_key, kind in INDICATOR_KIND_MAP.items():
            values = row.get(indicator_key)
            if isinstance(values, list):
                index.add_many(kind, values, source)
    return index


def extract_extended(text: str) -> Dict[str, List[str]]:
    """Indicator classes beyond the crawler's built-in set.

    Kept separate from Extractor so the crawl hot path and its existing output schema are
    untouched; the analysis stage calls this over already-saved page text.
    """
    body = text or ""
    dates = sorted(set(DATE_RE.findall(body)))[:200]
    name_candidates = sorted(set(NAME_CANDIDATE_RE.findall(body)))[:200]
    addresses = sorted({m.strip() for m in ADDRESS_RE.findall(body)})[:100]
    api_tokens = sorted(set(API_TOKEN_RE.findall(body)))[:100]
    jwts = sorted(set(JWT_RE.findall(body)))[:50]
    credential_pairs = [
        f"{user}:{secret}"
        for user, secret in CREDENTIAL_PAIR_RE.findall(body)
        if user.lower() not in _NOT_CREDENTIAL_KEYS
    ][:100]
    # Only the non-ASCII ones are worth carrying: the ASCII domains and handles are already
    # in the crawler's own indicator output.
    unicode_domains = sorted({
        m.strip(".") for m in UNICODE_DOMAIN_RE.findall(body) if _has_non_ascii(m)
    })[:100]
    unicode_handles = sorted({
        "@" + m for m in UNICODE_HANDLE_RE.findall(body) if _has_non_ascii(m)
    })[:100]

    return {
        "dates": dates,
        "name_candidates": name_candidates,
        "addresses": addresses,
        "api_tokens": api_tokens,
        "jwts": jwts,
        "credential_pairs": credential_pairs,
        "unicode_domains": unicode_domains,
        "unicode_handles": unicode_handles,
    }
