"""Immutable analysis bundles with atomic publication and durable attempt status."""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .checkpoints import EXTRACTOR_VERSION
from .storage import sync_directory, sync_file, write_json


def source_hashes(source):
    root = Path(source)
    files = [
        root / name
        for name in (
            "urls_crawled.jsonl",
            "indicators.jsonl",
            "page_scores.jsonl",
            "model_retry_latest.json",
            "run_manifest.json",
            "extraction_failures.jsonl",
        )
    ]
    for name in ("pages_text", "analysis"):
        files.extend(sorted((root / name).glob("*")))
    # Retry outputs are inputs whenever the reader overlays saved model responses.
    files.extend(sorted(root.glob("model_retry_*/analysis/*.json")))
    hashes = {}
    for path in files:
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        hashes[str(path.relative_to(root))] = digest.hexdigest()
    return hashes


def publish_analysis(source, options, ollama, run_id, log, output_dir):
    from .pipeline import _analyze_run, _write_artifacts, _write_rows
    from .report import write_analysis_report

    root = Path(output_dir or source).resolve()
    root.mkdir(parents=True, exist_ok=True)
    attempt = uuid.uuid4().hex
    staging = root / f".analysis_{attempt}.incomplete"
    final = root / f"analysis_{attempt}"
    staging.mkdir()
    status_path = root / f"analysis_{attempt}.status.json"
    status = {
        "status": "running",
        "started_at": time.time(),
        "source_run": str(Path(source).resolve()),
        "staging_directory": staging.name,
        "bundle_directory": final.name,
    }
    write_json(str(status_path), status)
    try:
        hashes = source_hashes(source)
        output = _analyze_run(source, options, ollama, run_id, log, str(staging))
        # Empty/failing runs still have a complete and readable bundle.
        if "analysis_summary" not in output.artifacts:
            _write_artifacts(str(staging), output)
        if "timeline" not in output.artifacts:
            _write_rows(str(staging / "timeline.jsonl"), [])
            output.artifacts["timeline"] = str(staging / "timeline.jsonl")
        output.artifacts["analysis_report"] = write_analysis_report(
            str(staging), output, run_id=run_id, scope={"source run": str(source)}
        )
        report_path = Path(output.artifacts["analysis_report"])
        report_path.write_text(
            report_path.read_text(encoding="utf-8").replace(f"RUN DIR: {staging}", f"RUN DIR: {final}"),
            encoding="utf-8",
        )
        training_manifest = staging / "training_export" / "manifest.json"
        if training_manifest.is_file():
            training = json.loads(training_manifest.read_text(encoding="utf-8"))
            training["run_dir"] = str(final)
            write_json(str(training_manifest), training)
        if source_hashes(source) != hashes:
            raise RuntimeError("Source artifacts changed during analysis; retry against a stable saved run")
        # Paths in the manifest refer to the final location, never the staging directory.
        output.artifacts = {
            key: str(final / Path(value).relative_to(staging)) for key, value in output.artifacts.items()
        }
        manifest = {
            "osintai_version": __version__,
            "extractor_version": EXTRACTOR_VERSION,
            "run_id": run_id,
            "status": "completed",
            "source_run": str(Path(source).resolve()),
            "source_hashes": hashes,
            "options": asdict(options),
            "analysis_stats": output.stats,
            "errors": output.errors,
            "artifacts": output.artifacts,
            "finished_at": time.time(),
            "model_stage_responses": {
                r.check_name: r.stats["model_response_counts"]
                for r in output.results
                if "model_response_counts" in r.stats
            },
        }
        write_json(str(staging / "run_manifest.json"), manifest)
        # Parse every structured output before publication and flush every file to disk.
        for path in staging.rglob("*"):
            if not path.is_file():
                continue
            with path.open("r", encoding="utf-8") as handle:
                if path.suffix == ".json":
                    json.load(handle)
                elif path.suffix == ".jsonl":
                    for line in handle:
                        if line.strip():
                            json.loads(line)
            sync_file(path)
        for directory in staging.rglob("*"):
            if directory.is_dir():
                sync_directory(directory)
        sync_directory(staging)
        os.replace(staging, final)
        sync_directory(root)
        status.update(
            status="completed",
            finished_at=time.time(),
            partial_coverage=bool(output.errors or output.stats.get("partial_coverage")),
        )
        write_json(str(status_path), status)
        write_json(str(root / "analysis_latest.json"), {"directory": final.name, "status": "completed"})
        output.artifacts["run_manifest"] = str(final / "run_manifest.json")
        return output
    except BaseException as exc:
        status.update(status="failed", finished_at=time.time(), error=f"{type(exc).__name__}: {exc}")
        write_json(str(status_path), status)
        raise
