"""Offline saved-crawl benchmark. Run from the repository with a saved RUN_ID.

Reports separate parent/maximum-child RSS (not aggregate concurrent memory).
Use separate invocations for cold and warm extraction-cache measurements.
"""

import argparse
import json
from pathlib import Path
import resource
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osintai.pipeline import AnalysisOptions, analyze_run, RunArtifacts
from osintai.cli import _validate_run_id


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "data" / "runs" / _validate_run_id(args.run_id)
    destination = (root / args.output).resolve()
    if not destination.is_relative_to(root):
        parser.error("benchmark output must stay inside the repository")
    start = time.perf_counter()
    output = analyze_run(
        str(source),
        AnalysisOptions(use_ollama=False),
        run_id=args.run_id,
        log=lambda message: print(message, flush=True),
    )
    factor = 1 if sys.platform == "darwin" else 1024
    result = {
        "run_id": args.run_id,
        "pages": len(RunArtifacts(str(source)).page_records()),
        "elapsed_seconds": round(time.perf_counter() - start, 3),
        "parent_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * factor,
        "max_child_peak_rss_bytes": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss * factor,
        "stats": output.stats,
        "errors": output.errors,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
