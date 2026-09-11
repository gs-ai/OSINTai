"""Reproducible offline boilerplate benchmark; prints timing and RSS as JSON."""

import argparse
import json
from pathlib import Path
import resource
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osintai.correlation import correlate
from osintai.entities import EntityIndex


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pages", type=int, default=10_000)
    parser.add_argument("--pair-budget", type=int, default=100_000)
    args = parser.parse_args()
    if args.pages < 1 or args.pair_budget < 1:
        parser.error("page count and pair budget must be positive")
    start = time.perf_counter()
    index = EntityIndex()
    for i in range(args.pages):
        url = f"https://site.test/{i}"
        for kind, value in (
            ("email", "footer@site.test"),
            ("username", "@footer"),
            ("name", "Site Footer"),
            ("phone", "5551112222"),
            ("email", f"person{i}@site.test"),
            ("username", f"@person{i}"),
        ):
            index.add(kind, value, url)
    indexed = time.perf_counter()
    result = correlate(index, [], page_count=args.pages, candidate_budget=args.pair_budget)
    factor = 1 if sys.platform == "darwin" else 1024
    print(
        json.dumps(
            {
                "pages": args.pages,
                "index_seconds": round(indexed - start, 3),
                "correlation_seconds": round(time.perf_counter() - indexed, 3),
                "parent_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * factor,
                "stats": result.stats,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
