"""Deterministic evaluation of model-assisted analysis quality.

The rubric measures entity accuracy, confidence language, source discipline, pivot
reasoning, and format compliance. Every check is computed in code against the page text the
analysis claims to describe, so the score is reproducible and stable across runs. Recurring
failure modes are aggregated because repeated weakness is more actionable than one outlier.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Callable, Dict, List, Optional, Tuple

from .provenance import (
    DERIVED,
    HIGH,
    LOW,
    MEDIUM,
    CheckResult,
    Finding,
    deterministic_confidence,
)

# Stable rubric weights; tests enforce that they remain normalized.
RUBRIC_WEIGHTS = {
    "entity_accuracy": 0.30,
    "confidence_language": 0.25,
    "source_discipline": 0.20,
    "pivot_reasoning": 0.15,
    "format_compliance": 0.10,
}

REQUIRED_KEYS = (
    "url", "title", "summary", "key_entities", "key_locations",
    "key_dates", "keywords", "risk_flags", "actionable_leads",
)

LIST_KEYS = (
    "key_entities", "key_locations", "key_dates",
    "keywords", "risk_flags", "actionable_leads",
)

# Language that asserts more than a single crawled page can support.
OVERSTATED = (
    "confirmed", "verified", "proven", "definitely", "certainly", "undoubtedly",
    "without a doubt", "conclusively", "establishes that", "proves",
)

# Language that correctly marks a claim as provisional.
HEDGED = (
    "appears", "indicated", "possible", "possibly", "unverified", "suggests",
    "may ", "might ", "reportedly", "claims", "requires confirmation", "unclear",
    "potential", "likely",
)

# A lead that is only a verb is not a lead.
VAGUE_LEADS = (
    "investigate further", "further investigation", "more research", "look into it",
    "additional analysis", "review the site", "monitor", "keep an eye",
)


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower())


def score_entity_accuracy(analysis: Dict[str, Any], page_text: str) -> Tuple[float, List[str]]:
    """Do the entities the model reported actually occur in the page it analyzed?"""
    entities = [e for e in (analysis.get("key_entities") or []) if isinstance(e, str) and e.strip()]
    if not entities:
        return 1.0, []  # Nothing claimed is not an accuracy failure.
    if not page_text:
        return 0.5, ["entity_accuracy: page text unavailable for verification"]

    haystack = _normalize(page_text)
    missing = [e for e in entities if _normalize(e) not in haystack]
    grounded = len(entities) - len(missing)
    score = grounded / len(entities)
    failures = []
    if missing:
        failures.append(
            f"entity_accuracy: {len(missing)}/{len(entities)} reported entities not found in page text"
        )
    return score, failures


def score_confidence_language(analysis: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Penalize overstatement, credit appropriate hedging."""
    text = _normalize(
        " ".join([
            str(analysis.get("summary") or ""),
            " ".join(str(f) for f in (analysis.get("risk_flags") or [])),
        ])
    )
    if not text.strip():
        return 1.0, []

    overstated = [term for term in OVERSTATED if term in text]
    hedged = [term for term in HEDGED if term in text]

    score = 1.0
    failures = []
    if overstated:
        score -= min(0.7, 0.25 * len(overstated))
        failures.append(f"confidence_language: overstated terms used ({', '.join(overstated[:4])})")
    if not hedged and len(text) > 200:
        score -= 0.15
        failures.append("confidence_language: no qualifying language in a substantive summary")
    return max(0.0, score), failures


def score_source_discipline(analysis: Dict[str, Any], page_text: str) -> Tuple[float, List[str]]:
    """Is the analysis anchored to the page it was given?"""
    failures = []
    score = 1.0

    if not str(analysis.get("url") or "").strip():
        score -= 0.4
        failures.append("source_discipline: analysis carries no source URL")

    summary = str(analysis.get("summary") or "")
    if summary and page_text:
        # Content words from the summary that never appear in the page suggest the model
        # drew on something other than the source it was given.
        words = {w for w in re.findall(r"[a-z]{6,}", summary.lower())}
        haystack = _normalize(page_text)
        if words:
            unsupported = sum(1 for w in words if w not in haystack)
            ratio = unsupported / len(words)
            if ratio > 0.6:
                score -= 0.4
                failures.append(
                    f"source_discipline: {ratio:.0%} of summary content words absent from page text"
                )
    elif not page_text:
        failures.append("source_discipline: page text unavailable for verification")
        score -= 0.1

    return max(0.0, score), failures


def score_pivot_reasoning(analysis: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Are the leads specific enough to act on?"""
    leads = analysis.get("actionable_leads") or []
    flat: List[str] = []
    for lead in leads:
        if isinstance(lead, str):
            flat.append(lead)
        elif isinstance(lead, dict):
            flat.append(str(lead.get("lead") or lead.get("description") or ""))
    flat = [l for l in flat if l.strip()]

    if not flat:
        return 0.6, ["pivot_reasoning: no actionable leads proposed"]

    vague = [l for l in flat if any(v in l.lower() for v in VAGUE_LEADS) and len(l) < 90]
    specific = len(flat) - len(vague)
    score = specific / len(flat)
    failures = []
    if vague:
        failures.append(f"pivot_reasoning: {len(vague)}/{len(flat)} leads are generic restatements")
    return score, failures


def score_format_compliance(analysis: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Did the model return the schema it was asked for?"""
    failures = []
    missing = [k for k in REQUIRED_KEYS if k not in analysis]
    wrong_type = [k for k in LIST_KEYS if k in analysis and not isinstance(analysis[k], list)]

    score = 1.0
    if missing:
        score -= min(0.8, 0.1 * len(missing))
        failures.append(f"format_compliance: missing keys ({', '.join(missing[:6])})")
    if wrong_type:
        score -= min(0.5, 0.15 * len(wrong_type))
        failures.append(f"format_compliance: non-list values for {', '.join(wrong_type[:4])}")
    if not isinstance(analysis.get("summary"), str):
        score -= 0.1
        failures.append("format_compliance: summary is not a string")
    return max(0.0, score), failures


def evaluate_analysis(
    analysis: Dict[str, Any], page_text: str, model: str = ""
) -> Dict[str, Any]:
    """Score one page analysis across all five rubric dimensions."""
    scores: Dict[str, float] = {}
    failures: List[str] = []

    for name, scorer in (
        ("entity_accuracy", lambda: score_entity_accuracy(analysis, page_text)),
        ("confidence_language", lambda: score_confidence_language(analysis)),
        ("source_discipline", lambda: score_source_discipline(analysis, page_text)),
        ("pivot_reasoning", lambda: score_pivot_reasoning(analysis)),
        ("format_compliance", lambda: score_format_compliance(analysis)),
    ):
        value, dimension_failures = scorer()
        scores[name] = round(max(0.0, min(1.0, value)), 4)
        failures.extend(dimension_failures)

    weighted = sum(scores[k] * RUBRIC_WEIGHTS[k] for k in RUBRIC_WEIGHTS)
    return {
        "url": analysis.get("url", ""),
        "model": model,
        "scores": scores,
        "weighted_score": round(weighted, 4),
        "failures": failures,
        "method": "deterministic_rubric",
    }


def evaluate_run(
    analyses: List[Dict[str, Any]],
    text_loader: Callable[[str], str],
    model: str = "",
    weak_threshold: float = 0.6,
) -> CheckResult:
    """Score every analysis in a run and rank the recurring failure modes."""
    result = CheckResult(check_name="Analysis Quality Evaluation")
    if not analyses:
        result.notes.append("No model analyses available. Evaluation skipped.")
        return result

    evaluations: List[Dict[str, Any]] = []
    failure_counter: Counter = Counter()

    for analysis in analyses:
        if not isinstance(analysis, dict) or analysis.get("error"):
            continue
        url = analysis.get("url") or ""
        evaluation = evaluate_analysis(analysis, text_loader(url), model=model)
        evaluations.append(evaluation)
        for failure in evaluation["failures"]:
            # Count the failure class, not the per-page numbers inside the message.
            failure_counter[failure.split(":")[0].strip()] += 1

    if not evaluations:
        result.notes.append("No parseable model analyses to evaluate.")
        return result

    weighted = [e["weighted_score"] for e in evaluations]
    mean = sum(weighted) / len(weighted)
    by_dimension = {
        dimension: round(
            sum(e["scores"][dimension] for e in evaluations) / len(evaluations), 4
        )
        for dimension in RUBRIC_WEIGHTS
    }

    result.rows = evaluations
    result.stats = {
        "evaluated": len(evaluations),
        "mean_weighted_score": round(mean, 4),
        "min_weighted_score": round(min(weighted), 4),
        "max_weighted_score": round(max(weighted), 4),
        "by_dimension": by_dimension,
        "dominant_failures": failure_counter.most_common(10),
        "rubric_weights": RUBRIC_WEIGHTS,
    }

    for dimension, score in sorted(by_dimension.items(), key=lambda kv: kv[1]):
        if score >= weak_threshold:
            continue
        result.findings.append(Finding(
            check="Analysis Quality",
            item=dimension,
            reason=(
                f"Mean {dimension.replace('_', ' ')} across {len(evaluations)} analyses is "
                f"{score:.2f}, below the {weak_threshold:.2f} threshold."
            ),
            next_step=(
                "Treat model output on this dimension with added scepticism for this run, and "
                "export weak examples for a separate, reviewed training workflow."
            ),
            origin=DERIVED,
            priority=HIGH if score < 0.4 else MEDIUM,
            sources=[e["url"] for e in evaluations if e["scores"][dimension] < weak_threshold][:25],
            evidence={"dimension": dimension, "mean": score, "weight": RUBRIC_WEIGHTS[dimension]},
            method="deterministic_rubric",
            model=model,
            confidence=[deterministic_confidence(0.85, "computed against page text, not model-graded")],
        ))

    result.notes.append(
        f"Evaluated {len(evaluations)} analysis output(s). Mean weighted score {mean:.3f}. "
        "Scoring is deterministic; no model graded another model."
    )
    return result


def weak_examples(evaluation_result: CheckResult, threshold: float = 0.6) -> List[Dict[str, Any]]:
    """Analyses that scored below threshold — the useful material for a training handoff."""
    return [
        row for row in evaluation_result.rows
        if isinstance(row, dict) and row.get("weighted_score", 1.0) < threshold
    ]
