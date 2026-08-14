"""Export evaluation and training material from a completed OSINT run.

OSINTai does not train. There is no trainer, no adapter, no MLX, no LoRA, no GGUF conversion
and no training dependency anywhere in this package, and nothing here runs unless the
operator passes the export flag.

Emitted files use portable JSON and JSONL formats:

  tasks.jsonl        {id, type, prompt, rubric}      evaluation task battery
  preferences.jsonl  {prompt, rejected, chosen, ...} preference pairs for later review
  scored.jsonl       per-analysis rubric scores
  manifest.json      provenance of the export

`chosen` is deliberately empty. Generating the corrected answer requires a model rewriting
another model's failure, which belongs in the training pipeline and not in a collection run.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Callable, Dict, List, Optional

from .evaluation import RUBRIC_WEIGHTS, weak_examples
from .provenance import CheckResult
from .storage import safe_mkdir, write_json

EXPORT_DIRNAME = "training_export"

# Stable task categories for downstream evaluation tooling.
TASK_ENTITY = "entity_extraction"
TASK_CONFIDENCE = "confidence_language"
TASK_SOURCE = "source_discipline"
TASK_PIVOT = "pivot_reasoning"
TASK_FORMAT = "format_compliance"

_FAILURE_TASK_TYPE = {
    "entity_accuracy": TASK_ENTITY,
    "confidence_language": TASK_CONFIDENCE,
    "source_discipline": TASK_SOURCE,
    "pivot_reasoning": TASK_PIVOT,
    "format_compliance": TASK_FORMAT,
}


def _write_jsonl(path: str, rows: List[Dict[str, Any]]) -> str:
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return path


def _weakest_dimension(scores: Dict[str, float]) -> str:
    return min(scores, key=lambda k: scores[k]) if scores else "entity_accuracy"


def build_tasks(
    evaluations: List[Dict[str, Any]],
    prompt_loader: Callable[[str], str],
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Build an evaluation battery from real pages this run struggled on.

    Real crawled pages make harder and more representative eval tasks than hand-written
    prompts, which makes the export useful for downstream evaluation.
    """
    tasks: List[Dict[str, Any]] = []
    for index, evaluation in enumerate(evaluations[:limit], start=1):
        url = evaluation.get("url", "")
        prompt = prompt_loader(url)
        if not prompt:
            continue
        scores = evaluation.get("scores", {})
        dimension = _weakest_dimension(scores)
        tasks.append({
            "id": f"OSINTAI-{index:04d}",
            "type": _FAILURE_TASK_TYPE.get(dimension, TASK_ENTITY),
            "prompt": prompt,
            "rubric": {
                "weakest_dimension": dimension,
                "observed_score": scores.get(dimension),
                "observed_weighted_score": evaluation.get("weighted_score"),
                "failures": evaluation.get("failures", []),
                "confidence_required": True,
                "source_attribution_required": True,
            },
            "source_url": url,
            "origin": "osintai_production_run",
        })
    return tasks


def build_preference_pairs(
    evaluations: List[Dict[str, Any]],
    analyses_by_url: Dict[str, Dict[str, Any]],
    prompt_loader: Callable[[str], str],
    threshold: float = 0.6,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """DPO pairs from analyses that scored badly against the rubric.

    The failing output becomes `rejected` with the specific failures attached. `chosen` is
    left empty for a separate, reviewed training workflow to construct.
    """
    pairs: List[Dict[str, Any]] = []
    for evaluation in evaluations:
        if evaluation.get("weighted_score", 1.0) >= threshold:
            continue
        url = evaluation.get("url", "")
        analysis = analyses_by_url.get(url)
        prompt = prompt_loader(url)
        if not analysis or not prompt:
            continue
        pairs.append({
            "task_id": f"OSINTAI-DPO-{len(pairs) + 1:04d}",
            "task_type": _FAILURE_TASK_TYPE.get(
                _weakest_dimension(evaluation.get("scores", {})), TASK_ENTITY
            ),
            "prompt": prompt,
            "rejected": json.dumps(analysis, ensure_ascii=False),
            "chosen": "",
            "chosen_status": "PENDING_REVIEW",
            "failures_addressed": evaluation.get("failures", []),
            "original_score": evaluation.get("weighted_score"),
            "dimension_scores": evaluation.get("scores", {}),
            "source_url": url,
            "model": evaluation.get("model", ""),
        })
        if len(pairs) >= limit:
            break
    return pairs


def export(
    run_dir: str,
    evaluation_result: CheckResult,
    analyses_by_url: Dict[str, Dict[str, Any]],
    prompt_loader: Callable[[str], str],
    model: str = "",
    run_id: str = "",
    threshold: float = 0.6,
) -> Dict[str, Any]:
    """Write the handoff package. Returns a summary of what was written.

    This is an export. It reads run artifacts and writes files. It does not fine-tune, does
    not modify a model, and does not contact anything.
    """
    out_dir = os.path.join(run_dir, EXPORT_DIRNAME)
    safe_mkdir(out_dir)

    evaluations = [r for r in evaluation_result.rows if isinstance(r, dict)]
    weak = weak_examples(evaluation_result, threshold=threshold)

    tasks = build_tasks(weak or evaluations, prompt_loader)
    pairs = build_preference_pairs(
        evaluations, analyses_by_url, prompt_loader, threshold=threshold
    )

    tasks_path = _write_jsonl(os.path.join(out_dir, "tasks.jsonl"), tasks)
    pairs_path = _write_jsonl(os.path.join(out_dir, "preferences.jsonl"), pairs)
    scored_path = _write_jsonl(os.path.join(out_dir, "scored.jsonl"), evaluations)

    manifest = {
        "produced_by": "OSINTai",
        "purpose": "training and evaluation dataset export",
        "run_id": run_id,
        "run_dir": run_dir,
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "analysis_model": model,
        "rubric_weights": RUBRIC_WEIGHTS,
        "weak_threshold": threshold,
        "counts": {
            "analyses_evaluated": len(evaluations),
            "weak_analyses": len(weak),
            "eval_tasks": len(tasks),
            "preference_pairs": len(pairs),
        },
        "quality_summary": evaluation_result.stats,
        "files": {
            "tasks": os.path.basename(tasks_path),
            "preferences": os.path.basename(pairs_path),
            "scored": os.path.basename(scored_path),
        },
        "notes": [
            "Scoring is deterministic and computed against page text; no model graded another model.",
            "Preference pairs carry `rejected` only. `chosen` requires a separate reviewed workflow.",
            "OSINTai performs no training. This package is an inert local export.",
        ],
    }
    manifest_path = os.path.join(out_dir, "manifest.json")
    write_json(manifest_path, manifest)

    return {
        "dir": out_dir,
        "tasks": tasks_path,
        "preferences": pairs_path,
        "scored": scored_path,
        "manifest": manifest_path,
        "counts": manifest["counts"],
    }
