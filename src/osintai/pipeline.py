"""The OSINTai analysis lifecycle.

Runs after the crawl, over saved artifacts. Disposable workers contain extraction and
expensive stages; content-addressed checkpoints support recovery. Completed reports are
published as immutable bundles without replacing source captures.

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
import sys
import math
from collections import OrderedDict
from functools import partial
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

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
from .storage import safe_mkdir, sha1, write_json, read_json
from .model_quality import page_status, summarize
from .isolation import isolated_call
from .checkpoints import ExtractionCache, extract_checkpoint

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
    max_text_chars: int = 200_000
    page_deadline_s: float = 30.0
    stage_deadline_s: float = 120.0
    candidate_pair_budget: int = 100_000
    text_cache_bytes: int = 16_000_000


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
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
            except ValueError:
                continue
    return rows


class RunArtifacts:
    """Reader for one run directory. Loads lazily and caches page text."""

    def __init__(self, run_dir: str, max_text_chars: int = 200_000, text_cache_bytes: int = 16_000_000):
        self.run_dir = run_dir
        self.text_dir = os.path.join(run_dir, "pages_text")
        self.analysis_dir = os.path.join(run_dir, "analysis")
        self._text_cache = OrderedDict()
        self.text_cache_bytes = text_cache_bytes
        self.cache_bytes = self.cache_peak_bytes = self.cache_evictions = 0
        self.missing_urls = set()
        self.unreadable_urls = set()
        self.max_text_chars = max_text_chars
        self.truncated_urls: Set[str] = set()

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
            self._text_cache.move_to_end(url)
            return self._text_cache[url]
        path = os.path.join(self.text_dir, f"{sha1(url)}.txt")
        text = ""
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    text = handle.read(self.max_text_chars + 1)
                    if len(text) > self.max_text_chars:
                        self.truncated_urls.add(url)
                        text = text[:self.max_text_chars]
            except OSError:
                self.unreadable_urls.add(url)
        else:
            self.missing_urls.add(url)
        size = sys.getsizeof(text) + sys.getsizeof(url) + 128
        if size <= self.text_cache_bytes:
            while self._text_cache and self.cache_bytes + size > self.text_cache_bytes:
                old_url, old_text = self._text_cache.popitem(last=False)
                self.cache_bytes -= sys.getsizeof(old_text) + sys.getsizeof(old_url) + 128
                self.cache_evictions += 1
            self._text_cache[url] = text
            self.cache_bytes += size
            self.cache_peak_bytes = max(self.cache_peak_bytes, self.cache_bytes)
        return text

    def coverage(self):
        return {"truncated": sorted(self.truncated_urls), "missing": sorted(self.missing_urls),
                "unreadable": sorted(self.unreadable_urls), "cache_peak_bytes": self.cache_peak_bytes,
                "cache_evictions": self.cache_evictions}

    def model_records(self):
        manifest = read_json(os.path.join(self.run_dir, "run_manifest.json"))
        default_model = manifest.get("analysis_model", "unknown") if isinstance(manifest, dict) else "unknown"
        latest = read_json(os.path.join(self.run_dir, "model_retry_latest.json"))
        retry_name = latest.get("directory", "") if isinstance(latest, dict) else ""
        # The pointer is local metadata, never an arbitrary path to read.
        retry_dir = os.path.join(self.run_dir, retry_name, "analysis") if retry_name.startswith("model_retry_") and os.path.basename(retry_name) == retry_name else ""
        rows = []
        for url in dict.fromkeys(record.get("url") for record in self.page_records() if record.get("url")):
            name = f"{sha1(url)}.analysis.json"
            path = os.path.join(self.analysis_dir, name)
            if retry_dir and os.path.isfile(os.path.join(retry_dir, name)):
                path = os.path.join(retry_dir, name)
            if not os.path.isfile(path):
                payload, status = {}, "missing"
            else:
                try:
                    with open(path, encoding="utf-8") as handle:
                        payload = json.load(handle)
                    status = page_status(payload)
                except (OSError, ValueError):
                    payload, status = {}, "invalid"
            model = payload.get("_model") if isinstance(payload, dict) else None
            model = model if isinstance(model, str) and model else default_model
            row = dict(payload) if status == "ok" else {}
            row.update(url=url, _model_status=status, _model=model if isinstance(model, str) else "unknown")
            rows.append(row)
        return rows

    def analyses(self) -> List[Dict[str, Any]]:
        return [row for row in self.model_records() if row["_model_status"] == "ok"]


def _run_stage(
    name: str, fn: Callable[[], CheckResult], output: AnalysisOutput, log: Callable[[str], None],
    timeout_s: float = 120.0
) -> Optional[CheckResult]:
    """Execute one stage under isolation. A stage failure is reported, never propagated."""
    started = time.time()
    log(f"[RUN]  {name}")
    try:
        result = isolated_call(fn, timeout_s=timeout_s)
    except Exception as exc:
        message = f"{name}: stage failed: {exc}"
        output.errors.append(message)
        log(f"[FAIL] analysis stage {name} -> {exc}")
        failed = CheckResult(check_name=name)
        failed.errors.append(str(exc))
        failed.stats["status"] = "timed_out" if isinstance(exc, TimeoutError) else "failed"
        failed.stats["partial_coverage"] = True
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


def _analyze_run(
    run_dir: str,
    options: AnalysisOptions,
    ollama=None,
    run_id: str = "",
    log: Optional[Callable[[str], None]] = None,
    output_dir: Optional[str] = None,
) -> AnalysisOutput:
    """Run the analysis lifecycle over a completed crawl."""
    log = log or (lambda message: None)
    output = AnalysisOutput()
    if options.max_text_chars < 1:
        raise ValueError("max_text_chars must be positive")
    artifacts = RunArtifacts(run_dir, options.max_text_chars, options.text_cache_bytes)
    cache = ExtractionCache(os.path.join(run_dir, ".extraction_cache"))
    run_dir = output_dir or run_dir
    safe_mkdir(run_dir)

    indicator_rows = artifacts.indicators()
    page_scores = artifacts.page_scores()
    page_records = artifacts.page_records()
    model_records = artifacts.model_records()
    output.stats["model_responses"] = summarize(model_records)
    analyses = [row for row in model_records if row["_model_status"] == "ok"]
    analyses_by_url = {a.get("url", ""): a for a in analyses if isinstance(a, dict)}

    if not indicator_rows and not page_records:
        output.stats["partial_coverage"] = True
        output.stats["extraction_failures"] = read_jsonl(os.path.join(artifacts.run_dir, "extraction_failures.jsonl"))
        output.errors.append("No crawl artifacts found; analysis skipped.")
        log("[SKIP] analysis: no crawl artifacts to analyze")
        return output

    # Entity index over the indicators the crawl already wrote.
    try:
        index: EntityIndex = isolated_call(index_indicators, indicator_rows, timeout_s=options.stage_deadline_s)
    except Exception as exc:
        output.errors.append(f"entity indexing failed: {exc}")
        index = EntityIndex()

    # Extended indicator classes over saved page text. Kept out of the crawl hot path so
    # the crawler's own output schema is unchanged.
    page_extras: Dict[str, Dict[str, Any]] = {}
    content_dates: Dict[str, List[str]] = {}
    scanned = 0
    extraction_failures = read_jsonl(os.path.join(artifacts.run_dir, "extraction_failures.jsonl"))
    total = min(len(page_records), MAX_TEXT_PAGES)
    for position, record in enumerate(page_records[:MAX_TEXT_PAGES], 1):
        url = record.get("url")
        if not url:
            continue
        text = artifacts.text_for(url)
        if not text:
            continue
        log(f"[SCAN] {position}/{total} {url} ({len(text)} chars)")
        try:
            key, metadata = cache.key(text, options.max_text_chars, url in artifacts.truncated_urls)
            extras = cache.get(key, metadata)
            if extras is None:
                extras = isolated_call(extract_checkpoint, text, timeout_s=options.page_deadline_s)
                try:
                    cache.put(key, metadata, extras)
                except OSError as exc:
                    output.errors.append(f"checkpoint write failed for {url}: {exc}; extracted results retained")
        except Exception as exc:
            extraction_failures.append({"url": url, "status": "timed_out" if isinstance(exc, TimeoutError) else "failed",
                                        "error": str(exc)})
            output.errors.append(f"extended extraction failed for {url}: {exc}")
            log(f"[FAIL] extraction {url}: {exc}")
            continue
        scanned += 1
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

    def run_stage(name, fn, output, log):
        return _run_stage(name, fn, output, log, timeout_s=options.stage_deadline_s)

    # Independent CPU stages run in disposable processes.
    run_stage("homoglyph analysis", partial(patterns.check_homoglyphs, index), output, log)
    run_stage(
        "sensitive infrastructure",
        partial(patterns.check_sensitive_infrastructure, index), output, log,
    )
    run_stage(
        "secret exposure",
        partial(patterns.check_secret_exposure, page_extras), output, log,
    )
    run_stage(
        "generated-content fingerprint",
        partial(_text_stage, "generated", artifacts.run_dir, options, page_records), output, log,
    )
    run_stage(
        "cross-source correlation",
        partial(correlation_module.correlate, index, indicator_rows, len(page_records), options.candidate_pair_budget),
        output, log,
    )

    temporal_result = run_stage("temporal analysis", partial(_temporal_stage, page_records, content_dates, options.gap_days), output, log)
    _write_rows(os.path.join(run_dir, "timeline.jsonl"), temporal_result.stats.pop("events", []) if temporal_result else [])
    output.artifacts["timeline"] = os.path.join(run_dir, "timeline.jsonl")
    run_stage(
        "recurring signals and outliers",
        partial(patterns.check_recurring_and_outliers, index, page_scores), output, log,
    )

    # Optional model-assisted stages. Nothing below runs unless it was asked for.
    evaluation_result: Optional[CheckResult] = None
    if options.evaluate:
        evaluation_result = run_stage(
            "analysis quality evaluation",
            partial(_text_stage, "evaluation", artifacts.run_dir, options, analyses),
            output, log,
        )

    if options.deep and options.use_ollama and ollama is not None:
        run_stage(
            "deep analysis",
            partial(_deep_analysis, ollama, options, index, output, page_scores, analyses, run_id),
            output, log,
        )

    if options.cross_check_models and options.use_ollama and ollama is not None:
        run_stage(
            "multi-model cross-check",
            partial(_cross_check, ollama, options, analyses), output, log,
        )

    # Hypotheses derive from the findings that now exist, so this runs after every stage
    # that can produce one.
    run_stage("hypothesis generation", partial(_hypothesis_stage, output.findings, index), output, log)
    run_stage("lead generation", partial(_lead_stage, index, options.max_leads_per_kind), output, log)

    if options.training_export and evaluation_result is not None:
        try:
            summary = isolated_call(_training_stage, run_dir, artifacts.run_dir, options,
                evaluation_result, analyses_by_url, page_records, run_id, timeout_s=options.stage_deadline_s)
            artifacts.truncated_urls.update(summary["text_coverage"]["truncated"])
            artifacts.missing_urls.update(summary["text_coverage"]["missing"])
            artifacts.unreadable_urls.update(summary["text_coverage"]["unreadable"])
            output.artifacts["training_export"] = summary["dir"]
            output.stats["training_export"] = summary["counts"]
            log(f"[OK]   training dataset exported: {summary['dir']}")
        except Exception as exc:
            import shutil
            shutil.rmtree(os.path.join(run_dir, "training_export"), ignore_errors=True)
            output.errors.append(f"training export failed: {exc}")
            log(f"[FAIL] training export -> {exc}")
    elif options.training_export:
        output.errors.append("training export requires --evaluate; nothing was exported.")
        log("[SKIP] training export: requires --evaluate")

    output.findings = sort_findings(output.findings)
    output.stats["finding_count"] = len(output.findings)
    output.stats["hypothesis_count"] = len(output.hypotheses)
    output.stats["lead_count"] = len(output.leads)
    for result in output.results:
        coverage = result.stats.get("text_coverage", {})
        artifacts.truncated_urls.update(coverage.get("truncated", []))
        artifacts.missing_urls.update(coverage.get("missing", []))
        artifacts.unreadable_urls.update(coverage.get("unreadable", []))
    output.stats["indicator_values_omitted"] = sum(
        count["omitted"] for extras in page_extras.values() for count in extras.get("extraction_coverage", {}).values())
    output.stats["extraction_failures"] = extraction_failures
    output.stats["extraction_cache"] = {"hits": cache.hits, "misses": cache.misses, "invalid": cache.invalid}
    output.stats["text_coverage"] = artifacts.coverage()
    output.stats["text_cache_budget_bytes"] = options.text_cache_bytes
    output.stats["text_char_limit"] = options.max_text_chars
    output.stats["pages_text_truncated"] = len(artifacts.truncated_urls)
    output.stats["pages_over_scan_limit"] = max(0, len(page_records) - MAX_TEXT_PAGES)
    if artifacts.truncated_urls:
        output.errors.append(
            f"Text truncated to {options.max_text_chars} characters on "
            f"{len(artifacts.truncated_urls)} page(s); analysis coverage is partial."
        )
        log(f"[WARN] {output.errors[-1]}")
    output.stats["model_coverage_partial"] = any(
        output.stats["model_responses"]["counts"][status] for status in ("empty", "invalid", "missing", "timed_out", "error"))
    output.stats["partial_coverage"] = bool(output.errors or extraction_failures or artifacts.missing_urls or artifacts.unreadable_urls
        or output.stats["pages_over_scan_limit"] or output.stats["indicator_values_omitted"]
        or ((options.use_ollama or options.evaluate) and output.stats["model_coverage_partial"]) or any(r.errors or r.stats.get("partial_coverage") for r in output.results))
    _write_artifacts(run_dir, output)
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

    result.stats = {"passes_run": len(result.rows), "model": options.model,
                    "model_response_counts": getattr(ollama, "response_counts", {})}
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
    result = multimodel.summarize_cross_checks(checks)
    result.stats["model_response_counts"] = getattr(ollama, "response_counts", {})
    return result


def _write_events(run_dir: str, events: List[temporal.Event], output: AnalysisOutput) -> None:
    path = os.path.join(run_dir, "timeline.jsonl")
    _write_rows(path, (event.to_dict() for event in events))
    output.artifacts["timeline"] = path


def _write_rows(path: str, rows: Iterable[Dict[str, Any]]) -> None:
    # Always create empty result files too; every advertised artifact must exist.
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def _write_artifacts(run_dir: str, output: AnalysisOutput) -> None:
    """Write the analysis artifacts. Existing crawl artifacts are never rewritten."""
    for name, rows in (
        ("findings.jsonl", [f.to_dict() for f in sort_findings(output.findings)]),
        ("hypotheses.jsonl", [h.to_dict() for h in output.hypotheses]),
        ("leads.jsonl", [l.to_dict() for l in output.leads]),
    ):
        path = os.path.join(run_dir, name)
        _write_rows(path, rows)
        output.artifacts[name.split(".")[0]] = path

    correlations = next(
        (r for r in output.results if r.check_name == "Cross-Source Correlation"), None
    )
    path = os.path.join(run_dir, "correlations.jsonl")
    _write_rows(path, correlations.rows if correlations else [])
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


def _text_stage(kind, source, options, rows):
    reader = RunArtifacts(source, options.max_text_chars, options.text_cache_bytes)
    if kind == "generated":
        result = patterns.check_generated_text(rows, reader.text_for)
    else:
        result = evaluation_module.evaluate_run(rows, reader.text_for, model=options.model)
    result.stats["text_coverage"] = reader.coverage()
    return result


def _temporal_stage(records, dates, gap_days):
    events, errors = temporal.build_events(records, dates)
    result = temporal.analyze_timeline(events, gap_threshold_days=gap_days)
    result.errors.extend(errors[:50])
    result.stats["events"] = [event.to_dict() for event in events]
    return result


def _hypothesis_stage(findings, index):
    result = CheckResult(check_name="Hypothesis Generation")
    result.hypotheses = hypotheses_module.from_findings(findings, index)
    return result


def _lead_stage(index, limit):
    result = CheckResult(check_name="Lead Generation")
    result.leads = pivots.generate_leads(index, per_kind=limit)
    return result


def analyze_run(run_dir, options, ollama=None, run_id="", log=None, output_dir=None):
    """Publish a validated immutable bundle, then atomically advance its pointer."""
    from .publication import publish_analysis
    for value in (options.max_text_chars, options.candidate_pair_budget, options.text_cache_bytes,
                  options.page_deadline_s, options.stage_deadline_s):
        if not math.isfinite(value) or value <= 0:
            raise ValueError("analysis limits and deadlines must be finite and positive")
    return publish_analysis(run_dir, options, ollama, run_id, log, output_dir)


def _training_stage(destination, source, options, evaluation_result, analyses_by_url, records, run_id):
    reader = RunArtifacts(source, options.max_text_chars, options.text_cache_bytes)
    records_by_url = {row.get("url"): row for row in records}

    def prompt_loader(url):
        text = reader.text_for(url)
        if not text:
            return ""
        return page_prompt(url, records_by_url.get(url, {}).get("title", ""), text, options.prompt_profile)

    summary = training_export_module.export(destination, evaluation_result, analyses_by_url,
                                            prompt_loader, model=options.model, run_id=run_id)
    summary["text_coverage"] = reader.coverage()
    return summary
