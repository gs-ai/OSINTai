"""Hypothesis generation from deterministic findings.

A hypothesis is an explanation that would account for what was observed. It is not a
finding, and OSINTai labels it as such at every point where it can be read: in the record,
in the artifact, and in the report.

Every hypothesis here is generated deterministically from findings that already exist, and
each one carries what would confirm it and what would refute it. That last part is what
separates a usable investigative hypothesis from a suggestion — a hypothesis nobody can
settle is not worth writing down.

Model-generated hypotheses are also supported (deep mode), and are labelled with the model
that produced them so the two kinds never blur together.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from .entities import DOMAIN, EMAIL, EntityIndex, PHONE, USERNAME
from .provenance import (
    CROSS_MODEL,
    HYPOTHESIS,
    Confidence,
    Finding,
    Hypothesis,
    MODEL_SELF,
    deterministic_confidence,
    model_self_confidence,
    source_support,
)


def _by_check(findings: List[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.check].append(finding)
    return grouped


def from_findings(findings: List[Finding], index: Optional[EntityIndex] = None) -> List[Hypothesis]:
    """Derive candidate explanations from the deterministic finding set."""
    grouped = _by_check(findings)
    hypotheses: List[Hypothesis] = []

    homoglyphs = grouped.get("Unicode / Homoglyph", [])
    for finding in homoglyphs:
        ascii_form = finding.evidence.get("ascii_normalization", "")
        hypotheses.append(Hypothesis(
            statement=(
                f"{finding.item!r} may be an impersonation of {ascii_form!r} rather than a "
                "distinct legitimate identifier."
            ),
            supporting=[finding.reason],
            contradicting=[
                "Non-ASCII characters are also normal for non-English organizations and personal names."
            ],
            sources=list(finding.sources),
            would_confirm=(
                "Registration or profile data showing the lookalike was created after the ASCII "
                "form and by an unrelated party, or content copied from the ASCII form's site."
            ),
            would_refute=(
                "Evidence that the same owner controls both forms, or that the identifier belongs "
                "to a language that legitimately uses those characters."
            ),
            follow_up="Compare WHOIS, certificate history, and site content for both forms.",
            method="homoglyph_finding",
            confidence=[deterministic_confidence(0.45, "derived from one deterministic finding")],
        ))

    secrets = grouped.get("Potential Secret Exposure", []) + grouped.get("Credential-Shaped Content", [])
    if secrets:
        sources = sorted({s for f in secrets for s in f.sources})
        hypotheses.append(Hypothesis(
            statement=(
                f"{len(sources)} crawled page(s) may be exposing live credential material through "
                "misconfiguration or an unredacted publication."
            ),
            supporting=[f"{len(secrets)} deterministic secret/credential finding(s)."],
            contradicting=[
                "Documentation, tutorials, and test fixtures routinely contain credential-shaped "
                "placeholder values."
            ],
            sources=sources[:25],
            would_confirm="The values resolve against a live service, or the host confirms an exposure.",
            would_refute="The values are documented examples, expired, or randomly generated placeholders.",
            follow_up=(
                "Review the pages in context. If exposure is real, notify the owner; do not test "
                "the credentials."
            ),
            method="secret_finding_cluster",
            confidence=[deterministic_confidence(0.4, "pattern evidence only")],
        ))

    correlations = grouped.get("Correlation Candidate", [])
    strong = [f for f in correlations if (f.evidence or {}).get("score", 0) >= 0.7]
    for finding in strong[:15]:
        evidence = finding.evidence or {}
        left = (evidence.get("left") or {}).get("value", "")
        right = (evidence.get("right") or {}).get("value", "")
        hypotheses.append(Hypothesis(
            statement=f"{left!r} and {right!r} may be controlled by the same party.",
            supporting=[finding.reason],
            contradicting=[
                "Co-occurrence on a page frequently reflects a directory, aggregator, or comment "
                "thread rather than shared control."
            ],
            sources=list(finding.sources),
            would_confirm=(
                "Both identifiers appearing together in registration data, an authored profile, or "
                "a record the subject controls."
            ),
            would_refute="Either identifier resolving to a clearly unrelated owner.",
            follow_up="Run the pivot list for both identifiers and compare the results.",
            method=f"correlation:{evidence.get('relation', '')}",
            confidence=[
                deterministic_confidence(float(evidence.get("score", 0.0)), "correlation candidate score"),
                source_support(list(finding.sources)),
            ],
        ))

    generated = grouped.get("Generated-Content Fingerprint", [])
    if len(generated) >= 3:
        sources = sorted({s for f in generated for s in f.sources})
        hypotheses.append(Hypothesis(
            statement=(
                f"The crawled site may publish machine-generated content at scale "
                f"({len(generated)} page(s) carry generation markers)."
            ),
            supporting=[f"{len(generated)} pages matched generated-text markers."],
            contradicting=[
                "The markers can also appear in pages that quote or discuss model output."
            ],
            sources=sources[:25],
            would_confirm="A sampling of pages showing uniform structure, timing, or byline patterns.",
            would_refute="The flagged pages are articles about language models rather than output from them.",
            follow_up="Sample the flagged pages before relying on the site as a primary source.",
            method="generated_content_cluster",
            confidence=[deterministic_confidence(0.5, f"{len(generated)} flagged pages")],
        ))

    gaps = grouped.get("Activity Gap", []) + grouped.get("Open Trailing Gap", [])
    for finding in gaps[:10]:
        hypotheses.append(Hypothesis(
            statement=(
                f"The dated-content gap at {finding.item} may reflect activity that moved off the "
                "crawled sources rather than activity that stopped."
            ),
            supporting=[finding.reason],
            contradicting=[
                "The gap may equally reflect this crawl's depth and scope rather than the subject's behavior."
            ],
            sources=list(finding.sources),
            would_confirm="Dated activity found on another channel inside the same window.",
            would_refute="A wider crawl of the same sources filling the gap with content.",
            follow_up="Widen depth or seed set across the gap window and re-run.",
            method="temporal_gap",
            confidence=[deterministic_confidence(0.35, "absence of evidence is not evidence of absence")],
        ))

    return hypotheses


def from_model(payload: Dict[str, Any], model: str, sources: List[str]) -> List[Hypothesis]:
    """Wrap model-proposed hypotheses so their origin is never lost.

    Anything the model returns arrives labelled HYPOTHESIS with the model recorded. Model
    self-confidence is kept as its own signal and does not become factual reliability.
    """
    items = payload.get("hypotheses") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return []

    hypotheses: List[Hypothesis] = []
    for item in items[:25]:
        if isinstance(item, str):
            statement, supporting, contradicting = item, [], []
            confirm = refute = follow_up = ""
            self_confidence = None
        elif isinstance(item, dict):
            statement = str(item.get("statement") or item.get("hypothesis") or "").strip()
            supporting = [str(s) for s in (item.get("supporting") or [])][:10]
            contradicting = [str(s) for s in (item.get("contradicting") or [])][:10]
            confirm = str(item.get("would_confirm") or "")
            refute = str(item.get("would_refute") or "")
            follow_up = str(item.get("follow_up") or item.get("recommended_follow_up") or "")
            self_confidence = item.get("confidence")
        else:
            continue

        if not statement:
            continue

        confidences = []
        if isinstance(self_confidence, (int, float)):
            value = float(self_confidence)
            confidences.append(model_self_confidence(value / 10.0 if value > 1 else value, model))

        hypotheses.append(Hypothesis(
            statement=statement,
            supporting=supporting,
            contradicting=contradicting or ["Not independently corroborated by deterministic analysis."],
            sources=sources[:25],
            would_confirm=confirm or "Not specified by the model.",
            would_refute=refute or "Not specified by the model.",
            follow_up=follow_up,
            method="model_deep_analysis",
            model=model,
            confidence=confidences,
        ))
    return hypotheses
