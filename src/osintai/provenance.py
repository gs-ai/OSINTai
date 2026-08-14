"""Provenance model for OSINTai analysis.

Every analytical statement OSINTai produces carries where it came from. A regex hit on a
crawled page, a calculation over those hits, something a local model said, and a proposed
explanation are four different kinds of claim, and the operator has to be able to tell them
apart in the report without reading the code that produced them.

Findings carry explicit origin, source, and confidence fields so observed data remains
separate from derived and model-assisted analysis.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Origin of a claim. Ordered weakest-commitment last.
OBSERVED = "OBSERVED"        # present in fetched source material
DERIVED = "DERIVED"          # computed deterministically from observed material
MODEL = "MODEL"              # produced by a language model
HYPOTHESIS = "HYPOTHESIS"    # a proposed explanation, not a finding

ORIGINS = (OBSERVED, DERIVED, MODEL, HYPOTHESIS)

# Investigator-facing priority.
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"

PRIORITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

# Confidence kinds are deliberately not interchangeable. A model reporting that it is
# certain is not the same class of evidence as three independent pages agreeing, and
# collapsing them into one number is how model output turns into apparent fact.
SOURCE_SUPPORT = "source_support"          # how many independent sources carry it
DETERMINISTIC = "deterministic"            # reproducible rule fired
MODEL_SELF = "model_self"                  # the model's own stated confidence
CROSS_MODEL = "cross_model"                # independent models agreed
HUMAN_REVIEW = "human_review"              # an operator confirmed it

CONFIDENCE_KINDS = (SOURCE_SUPPORT, DETERMINISTIC, MODEL_SELF, CROSS_MODEL, HUMAN_REVIEW)


def _clamp(value: float) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, value))


@dataclass
class Confidence:
    """A single confidence signal. Never merged across kinds."""

    kind: str
    value: float
    basis: str = ""

    def __post_init__(self) -> None:
        if self.kind not in CONFIDENCE_KINDS:
            raise ValueError(f"unknown confidence kind: {self.kind!r}")
        self.value = _clamp(self.value)

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "value": round(self.value, 4), "basis": self.basis}


@dataclass
class Finding:
    """One analytical statement with its provenance and its recommended next step.

    `next_step` is required in spirit: a finding an operator cannot act on is noise.
    """

    check: str
    item: str
    reason: str
    next_step: str
    origin: str = DERIVED
    priority: str = MEDIUM
    sources: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    method: str = ""
    model: str = ""
    confidence: List[Confidence] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.origin not in ORIGINS:
            raise ValueError(f"unknown origin: {self.origin!r}")
        if self.priority not in PRIORITY_ORDER:
            raise ValueError(f"unknown priority: {self.priority!r}")

    @property
    def is_model_derived(self) -> bool:
        return self.origin in (MODEL, HYPOTHESIS)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin,
            "priority": self.priority,
            "check": self.check,
            "item": self.item,
            "reason": self.reason,
            "next_step": self.next_step,
            "sources": self.sources,
            "evidence": self.evidence,
            "method": self.method,
            "model": self.model,
            "confidence": [c.to_dict() for c in self.confidence],
            "ts": self.ts,
        }


@dataclass
class Hypothesis:
    """A proposed explanation. Always labelled, never scored as an observation.

    Carries what would settle it, which is the part that makes a hypothesis useful to an
    investigator rather than just suggestive.
    """

    statement: str
    supporting: List[str] = field(default_factory=list)
    contradicting: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    would_confirm: str = ""
    would_refute: str = ""
    follow_up: str = ""
    method: str = ""
    model: str = ""
    confidence: List[Confidence] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    # Fixed. A hypothesis cannot be relabelled into an observation.
    origin: str = HYPOTHESIS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": HYPOTHESIS,
            "label": HYPOTHESIS,
            "statement": self.statement,
            "supporting": self.supporting,
            "contradicting": self.contradicting,
            "sources": self.sources,
            "would_confirm": self.would_confirm,
            "would_refute": self.would_refute,
            "follow_up": self.follow_up,
            "method": self.method,
            "model": self.model,
            "confidence": [c.to_dict() for c in self.confidence],
            "ts": self.ts,
        }


@dataclass
class Lead:
    """An actionable next action with a resolvable target."""

    label: str
    target: str
    rationale: str = ""
    seed: str = ""
    seed_type: str = ""
    sources: List[str] = field(default_factory=list)
    false_positive_risk: str = ""
    origin: str = DERIVED
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "origin": self.origin,
            "label": self.label,
            "target": self.target,
            "rationale": self.rationale,
            "seed": self.seed,
            "seed_type": self.seed_type,
            "sources": self.sources,
            "false_positive_risk": self.false_positive_risk,
            "ts": self.ts,
        }


@dataclass
class CheckResult:
    """Output of one analysis stage.

    Stages collect their problems instead of raising them. A missing input is a note, a bad
    record is an error, and either way the remaining stages still run and still report.
    """

    check_name: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    leads: List[Lead] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "rows": self.rows,
            "findings": [f.to_dict() for f in self.findings],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "leads": [l.to_dict() for l in self.leads],
            "notes": self.notes,
            "errors": self.errors,
            "stats": self.stats,
        }


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Highest priority first, then stable by check and item."""
    return sorted(
        findings,
        key=lambda f: (PRIORITY_ORDER.get(f.priority, 99), f.check, str(f.item)),
    )


def source_support(sources: List[str]) -> Confidence:
    """Confidence from breadth of independent corroboration.

    One page saying something is one page saying something. The curve is deliberately
    shallow: four independent sources reach 0.8, and nothing reaches 1.0, because crawled
    corroboration is not confirmation.
    """
    n = len({s for s in sources if s})
    if n <= 0:
        return Confidence(SOURCE_SUPPORT, 0.0, "no source reference")
    value = min(0.9, 0.35 + 0.15 * (n - 1))
    return Confidence(SOURCE_SUPPORT, value, f"{n} independent source(s)")


def deterministic_confidence(value: float, basis: str) -> Confidence:
    return Confidence(DETERMINISTIC, value, basis)


def model_self_confidence(value: float, model: str) -> Confidence:
    """The model's own stated confidence. Recorded, labelled, and never treated as fact."""
    return Confidence(MODEL_SELF, value, f"self-reported by {model or 'model'}")


def cross_model_confidence(agreeing: int, total: int) -> Confidence:
    if total <= 1:
        return Confidence(CROSS_MODEL, 0.0, "single model, no cross-check")
    return Confidence(
        CROSS_MODEL, agreeing / total, f"{agreeing}/{total} models agreed"
    )


def strongest(confidences: List[Confidence], kind: Optional[str] = None) -> Optional[Confidence]:
    pool = [c for c in confidences if kind is None or c.kind == kind]
    return max(pool, key=lambda c: c.value) if pool else None
