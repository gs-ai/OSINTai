import os
from typing import Any, Dict, List, Optional

from .provenance import (
    DERIVED,
    HYPOTHESIS,
    MODEL,
    OBSERVED,
    PRIORITY_ORDER,
    Finding,
    Hypothesis,
    Lead,
    sort_findings,
)
from .storage import write_json

RULE = "=" * 60
THIN = "-" * 60


def write_report(run_dir: str, ranked_pages: list):
    out_txt = os.path.join(run_dir, "report.txt")
    lines = []
    lines.append("OSINTai Report")
    lines.append("=" * 60)
    for i, p in enumerate(ranked_pages[:25], start=1):
        lines.append(f"{i:02d}. score={p.get('score')}  {p.get('url')}")
        if p.get("title"):
            lines.append(f"    title: {p.get('title')}")
        if p.get("summary"):
            lines.append(f"    summary: {p.get('summary')}")
        rf = p.get("risk_flags") or []
        if isinstance(rf, list) and rf:
            lines.append(f"    risk_flags: {', '.join([str(x) for x in rf])[:220]}")
        lines.append("")
    with open(out_txt, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    write_json(os.path.join(run_dir, "ranked_pages.json"), ranked_pages)
    return out_txt


# ---------------------------------------------------------------------------
# Analysis report
#
# report.txt above is unchanged and stays the ranked-pages report every existing
# consumer expects. The analysis report is a separate file covering what the analysis
# stage produced.
#
# An operator must be able to distinguish what a page said from what code computed and from
# what a model proposed without reading the implementation.
# ---------------------------------------------------------------------------

ORIGIN_SECTIONS = (
    (OBSERVED, "OBSERVED — PRESENT IN SOURCE MATERIAL"),
    (DERIVED, "DERIVED — COMPUTED FROM SOURCE MATERIAL"),
    (MODEL, "MODEL-ASSISTED — LANGUAGE MODEL INTERPRETATION"),
)


def _wrap(text: str, width: int = 96, indent: str = "      ") -> List[str]:
    words = str(text or "").split()
    if not words:
        return []
    lines, current = [], ""
    for word in words:
        if current and len(current) + 1 + len(word) > width:
            lines.append(indent + current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(indent + current)
    return lines


def _finding_block(finding: Finding, number: int) -> List[str]:
    lines = [f"  {number:02d}. [{finding.priority}] {finding.check}: {finding.item}"]
    lines.extend(_wrap(f"Why: {finding.reason}"))
    lines.extend(_wrap(f"Next step: {finding.next_step}"))
    if finding.method:
        lines.append(f"      Method: {finding.method}" + (f" (model: {finding.model})" if finding.model else ""))
    for confidence in finding.confidence:
        lines.append(
            f"      Confidence [{confidence.kind}]: {confidence.value:.2f} — {confidence.basis}"
        )
    if finding.sources:
        lines.append(f"      Sources ({len(finding.sources)}):")
        for source in finding.sources[:5]:
            lines.append(f"        - {source}")
        if len(finding.sources) > 5:
            lines.append(f"        ... and {len(finding.sources) - 5} more")
    lines.append("")
    return lines


def _hypothesis_block(hypothesis: Hypothesis, number: int) -> List[str]:
    lines = [f"  {number:02d}. [HYPOTHESIS] {hypothesis.statement}"]
    for support in hypothesis.supporting[:4]:
        lines.extend(_wrap(f"Supporting: {support}"))
    for against in hypothesis.contradicting[:4]:
        lines.extend(_wrap(f"Contradicting: {against}"))
    if hypothesis.would_confirm:
        lines.extend(_wrap(f"Would confirm: {hypothesis.would_confirm}"))
    if hypothesis.would_refute:
        lines.extend(_wrap(f"Would refute: {hypothesis.would_refute}"))
    if hypothesis.follow_up:
        lines.extend(_wrap(f"Follow up: {hypothesis.follow_up}"))
    if hypothesis.model:
        lines.append(f"      Origin: model-generated ({hypothesis.model})")
    elif hypothesis.method:
        lines.append(f"      Origin: derived from findings ({hypothesis.method})")
    for confidence in hypothesis.confidence:
        lines.append(
            f"      Confidence [{confidence.kind}]: {confidence.value:.2f} — {confidence.basis}"
        )
    if hypothesis.sources:
        lines.append(f"      Sources ({len(hypothesis.sources)}):")
        for source in hypothesis.sources[:4]:
            lines.append(f"        - {source}")
    lines.append("")
    return lines


def _section(title: str) -> List[str]:
    return ["", RULE, title, RULE, ""]


def write_analysis_report(
    run_dir: str,
    output,
    run_id: str = "",
    scope: Optional[Dict[str, Any]] = None,
) -> str:
    """Write analysis_report.txt covering findings, correlations, timeline, hypotheses and leads."""
    lines: List[str] = []
    findings = sort_findings(list(output.findings))

    lines.append("OSINTai Analysis Report")
    lines.append(RULE)
    if run_id:
        lines.append(f"RUN ID: {run_id}")
    lines.append(f"RUN DIR: {run_dir}")

    # SCOPE
    lines.extend(_section("SCOPE"))
    for key, value in (scope or {}).items():
        lines.append(f"  {key}: {value}")
    stats = output.stats or {}
    lines.append(f"  entities indexed: {stats.get('entities', 0)}")
    lines.append(f"  page texts scanned: {stats.get('pages_text_scanned', 0)}")
    lines.append(f"  findings: {len(findings)}")
    lines.append(f"  hypotheses: {len(output.hypotheses)}")
    lines.append(f"  leads: {len(output.leads)}")

    # HOW TO READ
    lines.extend(_section("HOW TO READ THIS REPORT"))
    lines.append("  OBSERVED    present in the fetched source material.")
    lines.append("  DERIVED     computed deterministically from observed material. Reproducible.")
    lines.append("  MODEL       a language model's interpretation. Not a measurement.")
    lines.append("  HYPOTHESIS  a proposed explanation. Not a finding.")
    lines.append("")
    lines.append("  Confidence signals are reported by kind and are not interchangeable.")
    lines.append("  A model's self-reported confidence is not evidence of reliability.")

    # STAGES
    lines.extend(_section("ANALYSIS STAGES"))
    for result in output.results:
        lines.append(f"  {result.check_name}: {result.finding_count} finding(s)")
        for note in result.notes:
            lines.extend(_wrap(note, indent="      "))
        for error in result.errors[:5]:
            lines.append(f"      Error: {error}")
        if len(result.errors) > 5:
            lines.append(f"      ... and {len(result.errors) - 5} more error(s)")
        lines.append("")

    # FINDINGS BY ORIGIN
    for origin, title in ORIGIN_SECTIONS:
        subset = [f for f in findings if f.origin == origin]
        lines.extend(_section(title))
        if not subset:
            lines.append("  No findings in this category.")
            continue
        for number, finding in enumerate(subset, start=1):
            lines.extend(_finding_block(finding, number))

    # CORRELATIONS
    correlations = next(
        (r for r in output.results if r.check_name == "Cross-Source Correlation"), None
    )
    lines.extend(_section("CROSS-SOURCE CORRELATIONS"))
    if correlations is None or not correlations.rows:
        lines.append("  No correlation candidates identified.")
    else:
        lines.append("  All entries are CANDIDATE links. No entities were merged.")
        lines.append("")
        for number, row in enumerate(correlations.rows[:40], start=1):
            left = row.get("left", {})
            right = row.get("right", {})
            lines.append(
                f"  {number:02d}. [{row.get('score', 0):.2f}] {left.get('value')} <-> {right.get('value')}"
            )
            lines.append(f"      relation: {row.get('relation')}  status: {row.get('status')}")
            lines.extend(_wrap(row.get("rationale", "")))
            lines.append(f"      evidence pages: {row.get('evidence_count', 0)}")
            lines.append("")
        if len(correlations.rows) > 40:
            lines.append(f"  ... and {len(correlations.rows) - 40} more in correlations.jsonl")

    # TIMELINE
    temporal_result = next(
        (r for r in output.results if r.check_name == "Temporal Analysis"), None
    )
    lines.extend(_section("TIMELINE"))
    if temporal_result is None or not temporal_result.rows:
        lines.append("  No dated events recovered.")
    else:
        stats = temporal_result.stats or {}
        lines.append(f"  Events: {stats.get('event_count', 0)}")
        lines.append(f"  Content dates: {stats.get('content_date_count', 0)}")
        lines.append(f"  Window: {stats.get('window_start', '')} to {stats.get('window_end', '')}")
        lines.append(f"  Span: {stats.get('window_days', 0)} day(s)")
        lines.append("")
        lines.append("  Full ordered event stream: timeline.jsonl")

    # HYPOTHESES
    lines.extend(_section("HYPOTHESES — NOT FINDINGS, NOT FACTS"))
    if not output.hypotheses:
        lines.append("  No hypotheses generated.")
    else:
        for number, hypothesis in enumerate(output.hypotheses, start=1):
            lines.extend(_hypothesis_block(hypothesis, number))

    # LEADS
    lines.extend(_section("LEADS — CANDIDATE LOOKUP PATHS"))
    if not output.leads:
        lines.append("  No leads generated.")
    else:
        lines.append("  A lead is a place to look, not a result. Opening it is how it is confirmed.")
        lines.append("")
        by_seed: Dict[str, List[Lead]] = {}
        for lead in output.leads:
            by_seed.setdefault(f"{lead.seed_type}: {lead.seed}", []).append(lead)
        for seed, seed_leads in list(by_seed.items())[:40]:
            lines.append(f"  {seed}")
            risk = seed_leads[0].false_positive_risk
            if risk:
                lines.extend(_wrap(f"False-positive risk: {risk}"))
            for lead in seed_leads[:8]:
                lines.append(f"      - {lead.label}: {lead.target}")
                if lead.rationale:
                    lines.extend(_wrap(lead.rationale, indent="          "))
            lines.append("")
        if len(by_seed) > 40:
            lines.append(f"  ... and {len(by_seed) - 40} more seeds in leads.jsonl")

    # RECOMMENDED NEXT STEPS
    lines.extend(_section("RECOMMENDED NEXT STEPS"))
    if not findings:
        lines.append("  No findings. Preserve the run artifacts and widen scope or depth to collect more.")
    else:
        for number, finding in enumerate(findings[:30], start=1):
            lines.append(f"  {number:02d}. [{finding.priority}] {finding.check} — {finding.item}")
            lines.extend(_wrap(finding.next_step, indent="        "))
        if len(findings) > 30:
            lines.append(f"  ... and {len(findings) - 30} more in findings.jsonl")

    if output.errors:
        lines.extend(_section("ANALYSIS ERRORS"))
        for error in output.errors:
            lines.append(f"  - {error}")

    lines.append("")
    out_txt = os.path.join(run_dir, "analysis_report.txt")
    with open(out_txt, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    return out_txt
