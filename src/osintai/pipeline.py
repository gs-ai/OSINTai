"""The OSINTai analysis lifecycle.

Runs after the crawl, over what the crawl already saved. The crawl itself is untouched: the
per-page fetch, extract, analyze, score path is exactly what it always was, and this stage
reads its output rather than changing it.

    RUN ARTIFACTS
          |
    NORMALIZE / INDEX ENTITIES
          |
    DETERMINISTIC ANALYSIS  (patterns, correlation, temporal)
          |
    MODEL-ASSISTED ANALYSIS (optional: deep analysis, cross-check)
          |
    CONFIDENCE / SUPPORT
          |
    HYPOTHESES / LEADS
          |
    REPORT

Each stage collects its problems into notes and errors instead of raising, and the
orchestrator wraps every stage so one failure cannot end the run. An analysis stage failing
must never cost the operator the crawl they just paid for.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import correlation as correlation_module
from . import evaluation as evaluation_module
from . import hypotheses as hypotheses_module
from . import multimodel
from . import patterns
from . import pivots
from . import temporal
from . import training_export as training_export_module
from .entities import (
    EntityIndex,
    extract_extended,
    index_indicators,
)
from .prompts import STANDARD, deep_analysis_prompt, page_prompt
from .provenance import (
    CheckResult,
    Finding,
    Hypothesis,
    Lead,
    sort_findings,
)
from .storage import append_jsonl, safe_mkdir, sha1, write_json

# Cap on page texts read back for extended extraction. A very large crawl should not turn
# the analysis stage into a second crawl-length operation.
MAX_TEXT_PAGES = 2000


@dataclass
class AnalysisOptions:
    """Everything the analysis stage can be asked to do. Defaults are the fast path."""

    deep: bool = False
    cross_check_models: List[str] = field(default_factory=list)
    evaluate: bool = False
    training_export: bool = False
    gap_days: int = 90
    prompt_profile: str = STANDARD
    model: str = ""
    use_ollama: bool = True
    experimental_recursive: int = 0
    max_leads_per_kind: int = 10


@dataclass
class AnalysisOutput:
    results: List[CheckResult] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    hypotheses: List[Hypothesis] = field(default_factory=list)
    leads: List[Lead] = field(default_factory=list)
    artifacts: Dict[str, str] = field(default_factory=dict)
    stats: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    rows: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    return rows


class RunArtifacts:
    """Reader for one run directory. Loads lazily and caches page text."""

    def __init__(self, run_dir: str):
        self.run_dir = run_dir
        self.text_dir = os.path.join(run_dir, "pages_text")
        self.analysis_dir = os.path.join(run_dir, "analysis")
        self._text_cache: Dict[str, str] = {}

    def indicators(self) -> List[Dict[str, Any]]:
        return read_jsonl(os.path.join(self.run_dir, "indicators.jsonl"))

    def page_scores(self) -> List[Dict[str, Any]]:
        return read_jsonl(os.path.join(self.run_dir, "page_scores.jsonl"))

    def page_records(self) -> List[Dict[str, Any]]:
        return read_jsonl(os.path.join(self.run_dir, "urls_crawled.jsonl"))

    def text_for(self, url: str) -> str:
        """Page text as the crawler saved it, keyed the same way the crawler keyed it."""
        if not url:
            return ""
        if url in self._text_cache:
            return self._text_cache[url]
        path = os.path.join(self.text_dir, f"{sha1(url)}.txt")
        text = ""
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read()
            except OSError:
                text = ""
        self._text_cache[url] = text
        return text

    def analyses(self) -> List[Dict[str, Any]]:
        if not os.path.isdir(self.analysis_dir):
            return []
        rows: List[Dict[str, Any]] = []
        for name in sorted(os.listdir(self.analysis_dir)):
            if not name.endswith(".analysis.json"):
                continue
            try:
                with open(os.path.join(self.analysis_dir, name), "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except (OSError, ValueError):
                continue
            if isinstance(payload, dict):
                rows.append(payload)
        return rows


def _run_stage(
    name: str, fn: Callable[[], CheckResult], output: AnalysisOutput, log: Callable[[str], None]
) -> Optional[CheckResult]:
    """Execute one stage under isolation. A stage failure is reported, never propagated."""
    started = time.time()
    try:
        result = fn()
    except Exception as exc:
        message = f"{name}: stage failed: {exc}"
        output.errors.append(message)
        log(f"[FAIL] analysis stage {name} -> {exc}")
        failed = CheckResult(check_name=name)
        failed.errors.append(str(exc))
        failed.notes.append("This stage failed. Remaining stages continued.")
        output.results.append(failed)
        return None

    elapsed = time.time() - started
    output.results.append(result)
    output.findings.extend(result.findings)
    output.hypotheses.extend(result.hypotheses)
    output.leads.extend(result.leads)
    log(f"[OK]   {name}: {result.finding_count} finding(s) in {elapsed:.2f}s")
    return result


def analyze_run(
    run_dir: str,
    options: AnalysisOptions,
    ollama=None,
    run_id: str = "",
    log: Optional[Callable[[str], None]] = None,
) -> AnalysisOutput:
    """Run the analysis lifecycle over a completed crawl."""
    log = log or (lambda message: None)
    output = AnalysisOutput()
    artifacts = RunArtifacts(run_dir)

    indicator_rows = artifacts.indicators()
    page_scores = artifacts.page_scores()
    page_records = artifacts.page_records()
    analyses = artifacts.analyses()
    analyses_by_url = {a.get("url", ""): a for a in analyses if isinstance(a, dict)}

    if not indicator_rows and not page_records:
        output.errors.append("No crawl artifacts found; analysis skipped.")
        log("[SKIP] analysis: no crawl artifacts to analyze")
        return output

    # Entity index over the indicators the crawl already wrote.
    index: EntityIndex = index_indicators(indicator_rows)

    # Extended indicator classes over saved page text. Kept out of the crawl hot path so
    # the crawler's own output schema is unchanged.
    page_extras: Dict[str, Dict[str, List[str]]] = {}
    content_dates: Dict[str, List[str]] = {}
    scanned = 0
    for record in page_records[:MAX_TEXT_PAGES]:
        url = record.get("url")
        if not url:
            continue
        text = artifacts.text_for(url)
        if not text:
            continue
        scanned += 1
        extras = extract_extended(text)
        page_extras[url] = extras
        if extras["dates"]:
            content_dates[url] = extras["dates"]
        index.add_many("date", extras["dates"], url)
        index.add_many("name", extras["name_candidates"], url)
        index.add_many("address", extras["addresses"], url)
        # Non-ASCII domains and handles the crawler's ASCII-only patterns cannot see.
        index.add_many("domain", extras["unicode_domains"], url)
        index.add_many("username", extras["unicode_handles"], url)

    # Dates the model reported are recorded too, marked by their source page.
    for analysis in analyses:
        url = analysis.get("url") or ""
        model_dates = [d for d in (analysis.get("key_dates") or []) if isinstance(d, str)]
        if url and model_dates:
            content_dates.setdefault(url, []).extend(model_dates)

    output.stats["entities"] = len(index)
    output.stats["pages_text_scanned"] = scanned
    log(f"[OK]   entity index: {len(index)} entities from {len(indicator_rows)} indicator record(s)")

    # Deterministic analysis. Cheap, offline, reproducible, always runs.
    _run_stage("homoglyph analysis", lambda: patterns.check_homoglyphs(index), output, log)
    _run_stage(
        "sensitive infrastructure",
        lambda: patterns.check_sensitive_infrastructure(index), output, log,
    )
    _run_stage(
        "secret exposure",
        lambda: patterns.check_secret_exposure(page_extras), output, log,
    )
    _run_stage(
        "generated-content fingerprint",
        lambda: patterns.check_generated_text(page_records, artifacts.text_for), output, log,
    )
    _run_stage(
        "cross-source correlation",
        lambda: correlation_module.correlate(index, indicator_rows, len(page_records)),
        output, log,
    )

    def temporal_stage() -> CheckResult:
        events, parse_errors = temporal.build_events(page_records, content_dates)
        result = temporal.analyze_timeline(events, gap_threshold_days=options.gap_days)
        result.errors.extend(parse_errors[:50])
        _write_events(run_dir, events, output)
        return result

    _run_stage("temporal analysis", temporal_stage, output, log)
    _run_stage(
        "recurring signals and outliers",
        lambda: patterns.check_recurring_and_outliers(index, page_scores), output, log,
    )

    # Optional model-assisted stages. Nothing below runs unless it was asked for.
    evaluation_result: Optional[CheckResult] = None
    if options.evaluate:
        evaluation_result = _run_stage(
            "analysis quality evaluation",
            lambda: evaluation_module.evaluate_run(
                analyses, artifacts.text_for, model=options.model
            ),
            output, log,
        )

    if options.deep and options.use_ollama and ollama is not None:
        _run_stage(
            "deep analysis",
            lambda: _deep_analysis(
                ollama, options, index, output, page_scores, analyses, run_id
            ),
            output, log,
        )

    if options.cross_check_models and options.use_ollama and ollama is not None:
        _run_stage(
            "multi-model cross-check",
            lambda: _cross_check(ollama, options, analyses), output, log,
        )

    # Hypotheses derive from the findings that now exist, so this runs after every stage
    # that can produce one.
    def hypothesis_stage() -> CheckResult:
        result = CheckResult(check_name="Hypothesis Generation")
        derived = hypotheses_module.from_findings(output.findings, index)
        result.hypotheses.extend(derived)
        result.notes.append(
            f"Derived {len(derived)} hypothesis/hypotheses from deterministic findings. "
            "Every entry is labelled HYPOTHESIS and is not an observed fact."
        )
        return result

    _run_stage("hypothesis generation", hypothesis_stage, output, log)

    def lead_stage() -> CheckResult:
        result = CheckResult(check_name="Lead Generation")
        generated = pivots.generate_leads(index, per_kind=options.max_leads_per_kind)
        result.leads.extend(generated)
        result.notes.append(
            f"Generated {len(generated)} pivot lead(s). Each is a candidate lookup path, not a hit; "
            "confirmation requires opening it."
        )
        return result

    _run_stage("lead generation", lead_stage, output, log)

    _write_artifacts(run_dir, output)

    if options.training_export and evaluation_result is not None:
        try:
            def prompt_loader(url: str) -> str:
                text = artifacts.text_for(url)
                if not text:
                    return ""
                record = next((r for r in page_records if r.get("url") == url), {})
                return page_prompt(url, record.get("title", ""), text, options.prompt_profile)

            summary = training_export_module.export(
                run_dir=run_dir,
                evaluation_result=evaluation_result,
                analyses_by_url=analyses_by_url,
                prompt_loader=prompt_loader,
                model=options.model,
                run_id=run_id,
            )
            output.artifacts["training_export"] = summary["dir"]
            output.stats["training_export"] = summary["counts"]
            log(f"[OK]   training dataset exported: {summary['dir']}")
        except Exception as exc:
            output.errors.append(f"training export failed: {exc}")
            log(f"[FAIL] training export -> {exc}")
    elif options.training_export:
        output.errors.append("training export requires --evaluate; nothing was exported.")
        log("[SKIP] training export: requires --evaluate")

    output.findings = sort_findings(output.findings)
    output.stats["finding_count"] = len(output.findings)
    output.stats["hypothesis_count"] = len(output.hypotheses)
    output.stats["lead_count"] = len(output.leads)
    return output


def _deep_analysis(
    ollama,
    options: AnalysisOptions,
    index: EntityIndex,
    output: AnalysisOutput,
    page_scores: List[Dict[str, Any]],
    analyses: List[Dict[str, Any]],
    run_id: str,
) -> CheckResult:
    """One run-level model pass over the deterministic results.

    Optional and bounded: one call, or a small number when recursive re-analysis is
    explicitly enabled. Recursive refinement is capped to keep work deterministic and bounded.
    """
    import asyncio

    result = CheckResult(check_name="Deep Analysis (model-assisted)")

    top_pages = sorted(page_scores, key=lambda p: p.get("score", 0), reverse=True)[:20]
    context = {
        "run_id": run_id,
        "pages_analyzed": len(page_scores),
        "top_pages": [
            {"url": p.get("url"), "score": p.get("score"), "summary": p.get("summary")}
            for p in top_pages
        ],
        "recurring_entities": [
            {"kind": e.kind, "value": e.value, "sources": len(e.sources)}
            for e in index.multi_source(minimum=2)[:40]
        ],
        "deterministic_findings": [
            {
                "check": f.check, "item": f.item, "reason": f.reason,
                "priority": f.priority, "origin": f.origin,
            }
            for f in sort_findings(output.findings)[:60]
        ],
    }

    sources = [p.get("url", "") for p in top_pages if p.get("url")]
    passes = 1 + max(0, min(3, options.experimental_recursive))
    payload: Optional[Dict[str, Any]] = None

    for pass_number in range(passes):
        prompt = deep_analysis_prompt(context)
        try:
            payload = asyncio.run(
                ollama.async_generate_json(options.model, prompt, timeout_s=180.0)
            )
        except RuntimeError as exc:
            result.errors.append(f"deep analysis pass {pass_number + 1} could not run: {exc}")
            break
        if not payload:
            result.errors.append(
                f"deep analysis pass {pass_number + 1} returned no parseable response."
            )
            break

        result.rows.append({
            "pass": pass_number + 1,
            "model": options.model,
            "assessment": payload.get("assessment", ""),
            "cross_source_observations": payload.get("cross_source_observations", []),
            "recommended_follow_up": payload.get("recommended_follow_up", []),
            "gaps": payload.get("gaps", []),
        })
        result.hypotheses.extend(
            hypotheses_module.from_model(payload, options.model, sources)
        )

        if pass_number + 1 >= passes:
            break
        # Experimental recursion feeds the prior pass back as context, bounded above.
        context = {
            "run_id": run_id,
            "previous_pass": payload,
            "deterministic_findings": context["deterministic_findings"],
            "instruction": "Refine the previous assessment. Remove anything unsupported.",
        }

    if payload is None and not result.errors:
        result.errors.append("Deep analysis produced no output.")

    result.stats = {"passes_run": len(result.rows), "model": options.model}
    result.notes.append(
        f"Deep analysis ran {len(result.rows)} model pass(es) with {options.model or 'the configured model'}. "
        "All output is model-generated interpretation, labelled as such, and is not observed fact."
    )
    return result


def _cross_check(ollama, options: AnalysisOptions, analyses: List[Dict[str, Any]]) -> CheckResult:
    import asyncio

    claims = multimodel.claims_from_analyses(analyses)
    if not claims:
        result = CheckResult(check_name="Multi-Model Cross-Check")
        result.notes.append("No model claims available to cross-check.")
        return result

    models = list(dict.fromkeys([options.model, *options.cross_check_models]))
    models = [m for m in models if m]
    try:
        checks = asyncio.run(multimodel.cross_check_claims(ollama, models, claims))
    except RuntimeError as exc:
        result = CheckResult(check_name="Multi-Model Cross-Check")
        result.errors.append(f"cross-check could not run: {exc}")
        return result
    return multimodel.summarize_cross_checks(checks)


def _write_events(run_dir: str, events: List[temporal.Event], output: AnalysisOutput) -> None:
    path = os.path.join(run_dir, "timeline.jsonl")
    if os.path.exists(path):
        os.remove(path)
    for event in events:
        append_jsonl(path, event.to_dict())
    output.artifacts["timeline"] = path


def _write_artifacts(run_dir: str, output: AnalysisOutput) -> None:
    """Write the analysis artifacts. Existing crawl artifacts are never rewritten."""
    for name, rows in (
        ("findings.jsonl", [f.to_dict() for f in sort_findings(output.findings)]),
        ("hypotheses.jsonl", [h.to_dict() for h in output.hypotheses]),
        ("leads.jsonl", [l.to_dict() for l in output.leads]),
    ):
        path = os.path.join(run_dir, name)
        if os.path.exists(path):
            os.remove(path)
        for row in rows:
            append_jsonl(path, row)
        output.artifacts[name.split(".")[0]] = path

    correlations = next(
        (r for r in output.results if r.check_name == "Cross-Source Correlation"), None
    )
    if correlations is not None:
        path = os.path.join(run_dir, "correlations.jsonl")
        if os.path.exists(path):
            os.remove(path)
        for row in correlations.rows:
            append_jsonl(path, row)
        output.artifacts["correlations"] = path

    summary_path = os.path.join(run_dir, "analysis_summary.json")
    write_json(summary_path, {
        "stages": [
            {
                "check_name": r.check_name,
                "findings": r.finding_count,
                "notes": r.notes,
                "errors": r.errors,
                "stats": r.stats,
            }
            for r in output.results
        ],
        "stats": output.stats,
        "errors": output.errors,
    })
    output.artifacts["analysis_summary"] = summary_path
