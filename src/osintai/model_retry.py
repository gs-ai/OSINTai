"""Explicit bounded model retries over saved text; original analyses stay intact."""

import asyncio
import os
import time
import math
import uuid
from pathlib import Path

from .model_quality import page_status, summarize
from .pipeline import RunArtifacts
from .prompts import page_prompt
from .publication import source_hashes
from .storage import write_json, sha1


async def retry_saved(
    source, ollama, model, limit=20, timeout_s=60.0, max_text_chars=200_000, prompt_profile="standard"
):
    if limit < 1 or not math.isfinite(timeout_s) or timeout_s <= 0 or max_text_chars < 1:
        raise ValueError("retry limits must be positive")
    reader = RunArtifacts(str(source), max_text_chars)
    records = reader.model_records()
    candidates = [row for row in records if row["_model_status"] != "ok"]
    root = Path(source)
    name = f"model_retry_{uuid.uuid4().hex}"
    staging, final = root / f".{name}.incomplete", root / name
    (staging / "analysis").mkdir(parents=True)
    status_path = root / f"{name}.status.json"
    status = {"status": "running", "model": model, "limit": limit, "timeout_s": timeout_s, "started_at": time.time()}
    write_json(str(status_path), status)
    outcomes = []
    try:
        hashes = source_hashes(str(source))
        # Preserve previous retry results when advancing the pointer after a small batch.
        for row in records:
            write_json(str(staging / "analysis" / f"{sha1(row['url'])}.analysis.json"), row)
        for row in candidates[:limit]:
            url = row["url"]
            text = reader.text_for(url)
            result = {"status": "missing", "payload": None}
            if text:
                try:
                    result = await asyncio.wait_for(
                        ollama.async_generate_result(
                            model, page_prompt(url, row.get("title", ""), text, prompt_profile), timeout_s=timeout_s
                        ),
                        timeout=timeout_s,
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    result = {"status": "timed_out", "payload": None}
                except Exception:
                    result = {"status": "error", "payload": None}
            status_value = page_status(result["payload"]) if result["status"] == "ok" else result["status"]
            payload = dict(result["payload"]) if status_value == "ok" else {}
            payload.update(url=url, _model=model, _model_status=status_value)
            write_json(str(staging / "analysis" / f"{sha1(url)}.analysis.json"), payload)
            outcomes.append(payload)
        if source_hashes(str(source)) != hashes:
            raise RuntimeError("Source artifacts changed during retry")
        status.update(
            status="completed",
            finished_at=time.time(),
            attempted=len(outcomes),
            omitted=max(0, len(candidates) - limit),
            model_responses=summarize(outcomes),
            source_hashes=hashes,
            text_coverage=reader.coverage(),
            max_text_chars=max_text_chars,
            prompt_profile=prompt_profile,
        )
        write_json(str(staging / "run_manifest.json"), status)
        os.replace(staging, final)
        write_json(str(status_path), status)
        write_json(str(root / "model_retry_latest.json"), {"directory": name})
        return str(final)
    except BaseException as exc:
        status.update(status="failed", finished_at=time.time(), error=type(exc).__name__)
        write_json(str(status_path), status)
        raise
