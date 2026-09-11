"""Cross-source correlation for OSINTai.

Two identifiers are related when the crawl produced evidence that they are related, and the
evidence travels with the link. Everything here is a scored *candidate*; nothing merges two
entities into one, because an entity merge made on a co-occurrence is not reversible once it
has propagated through a report.

Relationships are built from shared source evidence, never from coincidental list positions.
That preserves reversibility and prevents sorted data from manufacturing identities.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from heapq import nsmallest
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from .entities import (
    DOMAIN,
    EMAIL,
    Entity,
    EntityIndex,
    NAME,
    PHONE,
    USERNAME,
    canonical,
)
from .provenance import (
    DERIVED,
    HIGH,
    LOW,
    MEDIUM,
    CheckResult,
    Finding,
    deterministic_confidence,
    source_support,
)

# Relationship types
CO_OCCURS = "co_occurs_with"
SHARES_DOMAIN = "shares_domain_with"
LOCAL_PART_MATCH = "local_part_matches_handle"
NAME_MATCH = "name_matches_handle"
SAME_NUMBER = "same_number_written_differently"


@dataclass
class Correlation:
    """A candidate relationship between two entities, with the evidence that produced it."""

    left_kind: str
    left: str
    right_kind: str
    right: str
    relation: str
    evidence_urls: List[str] = field(default_factory=list)
    rationale: str = ""
    score: float = 0.0
    status: str = "CANDIDATE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "relation": self.relation,
            "left": {"kind": self.left_kind, "value": self.left},
            "right": {"kind": self.right_kind, "value": self.right},
            "evidence_urls": self.evidence_urls,
            "evidence_count": len(self.evidence_urls),
            "rationale": self.rationale,
            "score": round(self.score, 4),
        }


def _registrable(host: str) -> str:
    """Last two labels of a hostname. Good enough to group a site's own subdomains."""
    parts = [p for p in (host or "").split(".") if p]
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "")


def map_domains_to_urls(indicator_rows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Group crawled URLs under the domains that reference them, ranked by frequency."""
    domain_map: Dict[str, List[str]] = defaultdict(list)
    frequency: Counter = Counter()
    seen = defaultdict(set)

    for row in indicator_rows or []:
        source = row.get("url") or ""
        for url in row.get("urls") or []:
            try:
                host = (urlparse(url).hostname or "").lower()
            except ValueError:
                continue
            if not host:
                continue
            if url not in seen[host]:
                seen[host].add(url)
                if len(domain_map[host]) < 200:
                    domain_map[host].append(url)
            frequency[host] += 1
        source_host = (row.get("domain") or "").lower()
        if source_host and source not in seen[source_host]:
            seen[source_host].add(source)
            if len(domain_map[source_host]) < 200:
                domain_map[source_host].append(source)

    return {
        "total_domains": len(domain_map),
        "top_domains": frequency.most_common(25),
        "domain_map": {d: urls[:200] for d, urls in domain_map.items()},
    }


# An identifier present on this fraction of the crawled pages is site furniture — a
# footer contact, a masthead handle — not a per-page signal.
UBIQUITY_FRACTION = 0.25

# Pages carrying an enormous identifier set (directories, dumps, member lists) are skipped
# for pairing: everything co-occurs with everything there and the links mean nothing.
MAX_IDENTIFIERS_PER_PAGE = 60


def _site_wide(index: EntityIndex, page_count: int) -> set:
    """Entity keys that appear across so much of the crawl they carry no pairing signal."""
    if page_count < 8:
        return set()
    threshold = max(3, int(page_count * UBIQUITY_FRACTION))
    return {e.key for e in index.all() if len(e.sources) >= threshold}


def _co_occurrence_pairs(
    index: EntityIndex, page_count: int, candidate_budget: int = 100_000
) -> Tuple[List[Correlation], int, dict]:
    """Identifiers that appeared together on the same page.

    Site-wide identifiers are excluded from pairing. On a single-site crawl the contact
    address in the footer co-occurs with every handle on the site, and pairing them produces
    hundreds of links that describe the page template rather than the subject.
    """
    by_source = index.by_source()
    pair_evidence: Dict[Tuple[Tuple[str, str], Tuple[str, str]], List[str]] = defaultdict(list)
    linkable = {EMAIL, PHONE, USERNAME, NAME}
    ubiquitous = _site_wide(index, page_count)

    attempted = omitted = oversized = 0
    for url, entities in by_source.items():
        interesting = [
            e for e in entities if e.kind in linkable and e.key not in ubiquitous
        ]
        possible = len(interesting) * (len(interesting) - 1) // 2
        if len(interesting) > MAX_IDENTIFIERS_PER_PAGE:
            oversized += possible
            continue
        remaining = max(0, candidate_budget - attempted)
        omitted += max(0, possible - remaining)
        if remaining == 0 or possible == 0:
            continue
        ordered = sorted(interesting, key=lambda e: (e.kind, e.canonical_value))
        for i, left in enumerate(ordered):
            for right in ordered[i + 1:]:
                if attempted >= candidate_budget:
                    break
                attempted += 1
                key = (left.key, right.key)
                pair_evidence[key].append(url)

    correlations: List[Correlation] = []
    for (left_key, right_key), urls in pair_evidence.items():
        # A single shared page is weak; two or more independent pages is a real signal.
        score = min(0.85, 0.25 + 0.2 * (len(urls) - 1))
        correlations.append(Correlation(
            left_kind=left_key[0], left=left_key[1],
            right_kind=right_key[0], right=right_key[1],
            relation=CO_OCCURS,
            evidence_urls=urls[:25],
            rationale=(
                f"Both identifiers appear on {len(urls)} crawled page(s). Co-occurrence on a "
                "page is not proof of a shared owner."
            ),
            score=score,
        ))
    return correlations, len(ubiquitous), {
        "candidate_pair_budget": candidate_budget, "candidate_pairs_examined": attempted,
        "candidate_pairs_omitted": omitted, "oversized_page_pairs_omitted": oversized,
        "partial_coverage": bool(omitted or oversized),
    }


def _identity_hints(index: EntityIndex) -> List[Correlation]:
    """Shape-based identity candidates: email local parts, name forms, phone variants."""
    correlations: List[Correlation] = []
    handles = {e.canonical_value.lstrip("@"): e for e in index.of_kind(USERNAME)}
    prefixes = {}

    def evidence(left, right):
        small, large = sorted((left, right), key=lambda entity: len(entity.sources))
        shared = nsmallest(25, (url for url in small.sources if url in large._source_set))
        if shared:
            return shared, True
        for entity in (left, right):
            if entity.key not in prefixes:
                prefixes[entity.key] = nsmallest(25, entity.sources)
        return sorted(set(prefixes[left.key]) | set(prefixes[right.key]))[:25], False

    for email in index.of_kind(EMAIL):
        local = email.canonical_value.split("@", 1)[0]
        if len(local) < 4:
            continue
        handle = handles.get(local)
        if handle is None:
            continue
        urls, shared = evidence(email, handle)
        correlations.append(Correlation(
            left_kind=EMAIL, left=email.canonical_value,
            right_kind=USERNAME, right=handle.value,
            relation=LOCAL_PART_MATCH,
            evidence_urls=urls,
            rationale=(
                f"Email local part {local!r} matches the handle. Common local parts are reused "
                "widely by unrelated people; treat as a pivot, not an identity."
            ),
            score=0.55 if shared else 0.35,
        ))

    for name in index.of_kind(NAME):
        collapsed = name.canonical_value.replace(" ", "")
        handle = handles.get(collapsed)
        if handle is None:
            continue
        urls, shared = evidence(name, handle)
        correlations.append(Correlation(
            left_kind=NAME, left=name.value,
            right_kind=USERNAME, right=handle.value,
            relation=NAME_MATCH,
            evidence_urls=urls,
            rationale="Handle matches the name with separators removed.",
            score=0.4 if shared else 0.25,
        ))

    # Phone entities fold to a canonical digit key, so differently written forms of one
    # number land on one entity. This reports only where that genuinely happened: the claim
    # rests on the forms actually seen, not on the forms the number could be written in.
    for phone in index.of_kind(PHONE):
        if len(phone.observed_forms) > 1:
            correlations.append(Correlation(
                left_kind=PHONE, left=phone.canonical_value,
                right_kind=PHONE, right=", ".join(phone.observed_forms[:4]),
                relation=SAME_NUMBER,
                evidence_urls=list(phone.sources)[:25],
                rationale=(
                    f"One number written {len(phone.observed_forms)} different ways across the "
                    "crawl; these are the same number."
                ),
                score=0.8,
            ))

    return correlations


def _domain_families(index: EntityIndex) -> List[Correlation]:
    """Hosts sharing a registrable domain."""
    families: Dict[str, List[Entity]] = defaultdict(list)
    for entity in index.of_kind(DOMAIN):
        base = _registrable(entity.canonical_value)
        if base and base != entity.canonical_value:
            families[base].append(entity)

    correlations: List[Correlation] = []
    for base, members in families.items():
        if len(members) < 2:
            continue
        sources = list(dict.fromkeys(url for member in members for url in member.sources))
        correlations.append(Correlation(
            left_kind=DOMAIN, left=base,
            right_kind=DOMAIN, right=", ".join(nsmallest(8, (m.canonical_value for m in members))),
            relation=SHARES_DOMAIN,
            evidence_urls=sources[:25],
            rationale=f"{len(members)} hosts share the registrable domain {base}.",
            score=0.9,
        ))
    return correlations


# The full candidate set goes to the artifact; the report gets the top slice. A findings
# list nobody can read through is a findings list nobody reads.
MAX_CORRELATION_FINDINGS = 60
MAX_CORRELATION_ROWS = 20000


def correlate(
    index: EntityIndex, indicator_rows: Iterable[Dict[str, Any]], page_count: int = 0,
    candidate_budget: int = 100_000
) -> CheckResult:
    """Run every correlation method and report the candidates."""
    if candidate_budget < 1:
        raise ValueError("candidate_budget must be positive")
    result = CheckResult(check_name="Cross-Source Correlation")

    rows = list(indicator_rows or [])
    page_count = page_count or len(rows)
    domain_mapping = map_domains_to_urls(rows)

    correlations: List[Correlation] = []
    correlations.extend(_domain_families(index))
    correlations.extend(_identity_hints(index))
    co_occurrences, site_wide_count, coverage = _co_occurrence_pairs(index, page_count, candidate_budget)
    correlations.extend(co_occurrences)

    correlations.sort(key=lambda c: (-c.score, c.relation, c.left))
    truncated = max(0, len(correlations) - MAX_CORRELATION_ROWS)
    result.rows = [c.to_dict() for c in correlations[:MAX_CORRELATION_ROWS]]
    result.stats = {
        **coverage,
        "partial_coverage": coverage["partial_coverage"] or bool(truncated),
        "correlation_count": len(correlations),
        "rows_written": len(result.rows),
        "rows_truncated": truncated,
        "site_wide_identifiers_excluded": site_wide_count,
        "total_domains": domain_mapping["total_domains"],
        "top_domains": domain_mapping["top_domains"][:10],
    }

    if coverage["partial_coverage"]:
        result.notes.append("Candidate pairing coverage is partial; see omitted-pair counts.")

    # Only the strongest candidates become findings; the rest stay available in the artifact.
    promoted = 0
    for correlation in correlations:
        if correlation.score < 0.5:
            continue
        if promoted >= MAX_CORRELATION_FINDINGS:
            break
        promoted += 1
        priority = HIGH if correlation.score >= 0.8 else MEDIUM
        result.findings.append(Finding(
            check="Correlation Candidate",
            item=f"{correlation.left} <-> {correlation.right}",
            reason=f"{correlation.relation}: {correlation.rationale}",
            next_step=(
                "Open the evidence pages and establish whether these identifiers share an owner. "
                "Record the answer; do not treat the candidate link as established."
            ),
            origin=DERIVED,
            priority=priority,
            sources=correlation.evidence_urls,
            evidence=correlation.to_dict(),
            method=correlation.relation,
            confidence=[
                deterministic_confidence(correlation.score, correlation.rationale),
                source_support(correlation.evidence_urls),
            ],
        ))

    eligible = sum(1 for c in correlations if c.score >= 0.5)
    result.notes.append(
        f"Built {len(correlations)} candidate correlation(s) across {len(index)} entities "
        f"and {domain_mapping['total_domains']} domain(s). All links are candidates; no entities "
        "were merged."
    )
    if site_wide_count:
        result.notes.append(
            f"Excluded {site_wide_count} site-wide identifier(s) from co-occurrence pairing; "
            "they appear across too much of the crawl to indicate a specific relationship."
        )
    if eligible > promoted:
        result.notes.append(
            f"Promoted the {promoted} strongest candidate(s) to findings; the remaining "
            f"{eligible - promoted} scoring candidate(s) are in correlations.jsonl."
        )
    if truncated:
        result.notes.append(f"{truncated} lowest-scoring candidate(s) omitted from the artifact.")
    return result
