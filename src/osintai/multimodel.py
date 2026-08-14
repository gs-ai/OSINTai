"""Optional multi-model cross-checking and disagreement handling.

None of this runs unless the operator asks for it. OSINTai's default remains one model, one
call per page; expensive analysis that runs whether or not anyone wanted it is how a fast
tool stops being one.

Where models disagree, the disagreement is preserved. It is not averaged away, and a
majority does not silently become the answer. Two competent models reaching opposite
conclusions about a claim is itself a finding, and usually a more useful one than either
verdict alone.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .prompts import cross_check_prompt
from .provenance import (
    HIGH,
    LOW,
    MEDIUM,
    MODEL,
    CheckResult,
    Confidence,
    Finding,
    cross_model_confidence,
    model_self_confidence,
)

SUPPORTED = "supported"
UNSUPPORTED = "unsupported"
CONTRADICTED = "contradicted"
INSUFFICIENT = "insufficient_evidence"

VERDICTS = (SUPPORTED, UNSUPPORTED, CONTRADICTED, INSUFFICIENT)

# Verdicts that genuinely conflict, as opposed to merely differing in strength.
_OPPOSED = {(SUPPORTED, CONTRADICTED), (CONTRADICTED, SUPPORTED),
            (SUPPORTED, UNSUPPORTED), (UNSUPPORTED, SUPPORTED)}


@dataclass
class ModelVerdict:
    model: str
    verdict: str
    reason: str = ""
    confidence: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "verdict": self.verdict,
            "reason": self.reason,
            "self_confidence": round(self.confidence, 4),
            "error": self.error,
        }


@dataclass
class CrossCheck:
    """One claim assessed by several models, with agreement state preserved."""

    claim: str
    sources: List[str] = field(default_factory=list)
    verdicts: List[ModelVerdict] = field(default_factory=list)

    @property
    def answered(self) -> List[ModelVerdict]:
        return [v for v in self.verdicts if not v.error and v.verdict in VERDICTS]

    @property
    def agreement(self) -> str:
        answered = self.answered
        if len(answered) < 2:
            return "not_cross_checked"
        distinct = {v.verdict for v in answered}
        if len(distinct) == 1:
            return "unanimous"
        for left in distinct:
            for right in distinct:
                if (left, right) in _OPPOSED:
                    return "contradictory"
        return "divided"

    @property
    def majority(self) -> Optional[str]:
        """The most common verdict, or None when models are evenly split.

        Reported as a count, never as the answer.
        """
        answered = self.answered
        if not answered:
            return None
        counts = Counter(v.verdict for v in answered).most_common()
        if len(counts) > 1 and counts[0][1] == counts[1][1]:
            return None
        return counts[0][0]

    def to_dict(self) -> Dict[str, Any]:
        answered = self.answered
        agreeing = sum(1 for v in answered if v.verdict == self.majority) if self.majority else 0
        return {
            "claim": self.claim,
            "sources": self.sources,
            "agreement": self.agreement,
            "majority_verdict": self.majority,
            "agreeing": agreeing,
            "answered": len(answered),
            "requested": len(self.verdicts),
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


def _parse_verdict(model: str, payload: Optional[Dict[str, Any]]) -> ModelVerdict:
    if not isinstance(payload, dict):
        return ModelVerdict(model=model, verdict="", error="no parseable response")
    verdict = str(payload.get("verdict", "")).strip().lower().replace(" ", "_")
    if verdict not in VERDICTS:
        return ModelVerdict(model=model, verdict="", error=f"unrecognized verdict {verdict!r}")
    raw_confidence = payload.get("confidence", 0.0)
    try:
        confidence = float(raw_confidence)
    except (TypeError, ValueError):
        confidence = 0.0
    if confidence > 1:
        confidence = confidence / 10.0
    return ModelVerdict(
        model=model,
        verdict=verdict,
        reason=str(payload.get("reason", ""))[:400],
        confidence=max(0.0, min(1.0, confidence)),
    )


async def cross_check_claims(
    ollama,
    models: List[str],
    claims: List[Tuple[str, str, List[str]]],
    timeout_s: float = 90.0,
    max_parallel: int = 2,
) -> List[CrossCheck]:
    """Put each claim to every model. `claims` is (claim, context, sources).

    Model failure is tolerated per verdict: one unreachable model leaves its slot marked with
    an error and the remaining verdicts still form a cross-check.
    """
    if not models or not claims:
        return []

    semaphore = asyncio.Semaphore(max(1, max_parallel))
    results: List[CrossCheck] = []

    async def ask(model: str, prompt: str) -> ModelVerdict:
        async with semaphore:
            try:
                payload = await ollama.async_generate_json(model, prompt, timeout_s)
            except Exception as exc:
                return ModelVerdict(model=model, verdict="", error=str(exc)[:200])
        return _parse_verdict(model, payload)

    for claim, context, sources in claims:
        prompt = cross_check_prompt(claim, context)
        verdicts = await asyncio.gather(*[ask(model, prompt) for model in models])
        results.append(CrossCheck(claim=claim, sources=list(sources), verdicts=list(verdicts)))

    return results


def summarize_cross_checks(checks: List[CrossCheck]) -> CheckResult:
    """Turn cross-check outcomes into findings, keeping disagreement visible."""
    result = CheckResult(check_name="Multi-Model Cross-Check")
    if not checks:
        result.notes.append("Multi-model cross-check not requested.")
        return result

    contradictory = 0
    for check in checks:
        payload = check.to_dict()
        result.rows.append(payload)
        answered = check.answered
        agreement = check.agreement

        if agreement == "not_cross_checked":
            result.errors.append(
                f"Claim cross-check incomplete ({len(answered)}/{len(check.verdicts)} models answered): "
                f"{check.claim[:100]}"
            )
            continue

        if agreement == "contradictory":
            contradictory += 1
            positions = "; ".join(
                f"{v.model} says {v.verdict}" + (f" ({v.reason[:80]})" if v.reason else "")
                for v in answered
            )
            result.findings.append(Finding(
                check="Model Disagreement",
                item=check.claim[:200],
                reason=f"Models reached opposing verdicts. {positions}",
                next_step=(
                    "Resolve this against the source material directly. The disagreement is "
                    "recorded unresolved; no model's verdict has been adopted."
                ),
                origin=MODEL,
                priority=HIGH,
                sources=check.sources,
                evidence=payload,
                method="multi_model_cross_check",
                model=", ".join(v.model for v in answered),
                confidence=[
                    cross_model_confidence(0, len(answered)),
                    *[model_self_confidence(v.confidence, v.model) for v in answered],
                ],
            ))
            continue

        agreeing = sum(1 for v in answered if v.verdict == check.majority)
        priority = LOW if agreement == "unanimous" else MEDIUM
        result.findings.append(Finding(
            check="Cross-Model Assessment",
            item=check.claim[:200],
            reason=(
                f"{agreeing}/{len(answered)} models returned {check.majority!r}"
                + (" (unanimous)." if agreement == "unanimous" else " (divided).")
            ),
            next_step=(
                "Agreement between models indicates consistency, not verification. Confirm "
                "against the source before relying on it."
            ),
            origin=MODEL,
            priority=priority,
            sources=check.sources,
            evidence=payload,
            method="multi_model_cross_check",
            model=", ".join(v.model for v in answered),
            confidence=[
                cross_model_confidence(agreeing, len(answered)),
                *[model_self_confidence(v.confidence, v.model) for v in answered],
            ],
        ))

    result.stats = {
        "claims_checked": len(checks),
        "contradictory": contradictory,
        "unanimous": sum(1 for c in checks if c.agreement == "unanimous"),
        "divided": sum(1 for c in checks if c.agreement == "divided"),
    }
    result.notes.append(
        f"Cross-checked {len(checks)} claim(s). {contradictory} produced contradictory verdicts, "
        "which are preserved rather than resolved."
    )
    return result


def claims_from_analyses(
    analyses: List[Dict[str, Any]], limit: int = 12
) -> List[Tuple[str, str, List[str]]]:
    """Pick the model claims most worth a second opinion.

    Risk flags first: they are the highest-weighted input to the page score, so an
    unsupported one distorts the ranking more than anything else the model says.
    """
    claims: List[Tuple[str, str, List[str]]] = []
    for analysis in analyses:
        if not isinstance(analysis, dict):
            continue
        url = analysis.get("url") or ""
        summary = str(analysis.get("summary") or "")
        for flag in (analysis.get("risk_flags") or [])[:3]:
            if not isinstance(flag, str) or not flag.strip():
                continue
            claims.append((
                f"The page at {url} supports this risk assessment: {flag}",
                f"Page summary: {summary}",
                [url],
            ))
            if len(claims) >= limit:
                return claims
    return claims
