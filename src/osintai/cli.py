import os
import sys
import argparse
import json
import asyncio
import re
import time
from urllib.parse import urlparse

from osintai.storage import safe_mkdir, now_run_id, load_lines, write_json
from osintai.extractor import Extractor
from osintai.proxy_pool import ProxyPool
from osintai.fetcher import AsyncFetcher
from osintai.crawler import AsyncCrawler
from osintai.scoring import rank_pages
from osintai.report import write_report, write_analysis_report
from osintai.ollama_api import OllamaAPI
from osintai.pipeline import AnalysisOptions, analyze_run
from osintai.prompts import PAGE_PROFILES, STANDARD
from osintai import __version__

RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Named run profiles. `survey` encodes the deeper, narrower, politer parameters from the
# OSINTai run template: go further into one target and go easier on its server.
RUN_PROFILES = {
    "default": {},
    "survey": {
        "depth": 3,
        "max": 300,
        "same_domain": True,
        "concurrency": 10,
        "per_host": 3,
    },
}

def _read_jsonl(path: str):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except (json.JSONDecodeError, TypeError):
                continue
    return rows


def _valid_seed_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def _load_seed_file(path: str) -> list[str]:
    """Load and validate HTTP(S) seed URLs, preserving their file order."""
    seeds: list[str] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue
            if not _valid_seed_url(value):
                raise ValueError(f"{path}:{line_number}: invalid HTTP(S) URL: {value!r}")
            seeds.append(value)
    return seeds


def _validate_run_id(value: str) -> str:
    """Keep every run directory beneath data/runs and portable across platforms."""
    candidate = (value or "").strip()
    if not RUN_ID_PATTERN.fullmatch(candidate) or candidate in {".", ".."}:
        raise ValueError(
            "run ID must be 1-128 characters using letters, numbers, '.', '_' or '-', "
            "and must start with a letter or number"
        )
    return candidate


def _resolve_seed_urls(
    seed_values: list[str] | None, seed_file: str | None, base_dir: str
) -> list[str]:
    """Resolve explicit inputs first, then the documented project seed file."""
    seeds: list[str] = []
    if seed_file:
        path = os.path.abspath(os.path.expanduser(seed_file))
        if not os.path.isfile(path):
            raise ValueError(f"seed file does not exist or is not readable: {path}")
        seeds.extend(_load_seed_file(path))

    for value in seed_values or []:
        value = value.strip()
        if not _valid_seed_url(value):
            if os.path.isfile(os.path.expanduser(value)):
                raise ValueError(
                    f"--seed expects a URL; use --seed-file {value!r} for a file"
                )
            raise ValueError(f"invalid HTTP(S) seed URL: {value!r}")
        seeds.append(value)

    if not seeds and not seed_file and not seed_values:
        # Keep convenient file-only operation, using the path documented in README.
        default_file = os.path.join(base_dir, "seed_urls.txt")
        legacy_file = os.path.join(base_dir, "OSINTai_FILES1", "seeds", "seed_urls.txt")
        for path in (default_file, legacy_file):
            if os.path.isfile(path):
                seeds.extend(_load_seed_file(path))
                break

    # Ordered de-duplication prevents redundant work without changing priority.
    return list(dict.fromkeys(seeds))

def main():
    ap = argparse.ArgumentParser(
        description=f"OSINTai v{__version__.split('.')[0]} (async crawling and analysis)"
    )
    ap.add_argument("--version", action="version", version=f"OSINTai {__version__}")
    ap.add_argument(
        "--seed", action="append", help="Seed HTTP(S) URL; may be supplied multiple times"
    )
    ap.add_argument("--seed-file", help="Text file containing one HTTP(S) seed URL per line")
    ap.add_argument("--depth", type=int, default=2, help="Max depth")
    ap.add_argument("--max", type=int, default=150, help="Max URLs")
    ap.add_argument("--same-domain", action="store_true", help="Only crawl same domain as seed")

    ap.add_argument("--concurrency", type=int, default=18, help="Global concurrency")
    ap.add_argument("--per-host", type=int, default=4, help="Per-host concurrency")
    ap.add_argument(
        "--max-response-bytes",
        type=int,
        default=2_000_000,
        help="Maximum decoded HTML response size (default: 2000000)",
    )

    ap.add_argument("--ua", default="user_agents.txt", help="User agents file")
    ap.add_argument("--proxies", default="", help="Optional proxy list file")

    ap.add_argument("--model", default="osint-tuned-v3:latest", help="Ollama analyze model")
    ap.add_argument("--embed-model", default="bge-m3:latest", help="Ollama embeddings model")
    ap.add_argument("--no-ollama", action="store_true", help="Disable LLM analysis and embeddings")

    ap.add_argument("--hunt", default="", help="Comma-separated hunt terms")
    ap.add_argument("--hunt-max", type=int, default=50, help="Max lead URLs per page from hunt mode")

    ap.add_argument("--run-id", default="", help="Optional run id override")

    ap.add_argument(
        "--profile",
        default="default",
        choices=sorted(RUN_PROFILES),
        help="Named run profile applied before explicit flags (default: default)",
    )
    ap.add_argument(
        "--prompt-profile",
        default=STANDARD,
        choices=sorted(PAGE_PROFILES),
        help="Page analysis lens (default: standard)",
    )

    ap.add_argument(
        "--no-analysis",
        action="store_true",
        help="Skip the post-crawl analysis stage (crawl and report only)",
    )
    ap.add_argument(
        "--deep",
        action="store_true",
        help="Optional: run a model-assisted run-level analysis pass",
    )
    ap.add_argument(
        "--cross-check",
        default="",
        help="Optional: comma-separated additional Ollama models to cross-check claims against",
    )
    ap.add_argument(
        "--evaluate",
        action="store_true",
        help="Optional: score analysis quality against the investigative rubric (deterministic)",
    )
    ap.add_argument(
        "--training-export",
        action="store_true",
        help="Optional: export local training/evaluation datasets (requires --evaluate)",
    )
    ap.add_argument(
        "--gap-days",
        type=int,
        default=90,
        help="Temporal gap threshold in days (default: 90)",
    )
    ap.add_argument(
        "--leads-per-kind",
        type=int,
        default=10,
        help="Max entities of each kind expanded into pivot leads (default: 10)",
    )
    ap.add_argument(
        "--experimental-recursive",
        type=int,
        default=0,
        metavar="N",
        help="EXPERIMENTAL: extra bounded deep-analysis refinement passes, 0-3 (default: 0)",
    )

    argv = list(sys.argv[1:])
    args = ap.parse_args()

    # A profile supplies values the operator did not state. An explicit flag always wins.
    profile_values = RUN_PROFILES.get(args.profile, {})
    profile_applied = []
    for dest, value in profile_values.items():
        flag = "--" + dest.replace("_", "-")
        if flag in argv:
            continue
        setattr(args, dest, value)
        profile_applied.append(f"{dest}={value}")

    if not 0 <= args.experimental_recursive <= 3:
        ap.error("--experimental-recursive must be between 0 and 3")
    if args.gap_days < 1:
        ap.error("--gap-days must be greater than zero")
    if args.training_export and not args.evaluate:
        ap.error("--training-export requires --evaluate")

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    try:
        seed_urls = _resolve_seed_urls(args.seed, args.seed_file, base_dir)
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    if not seed_urls:
        ap.error("No seed URLs found. Provide --seed URL or --seed-file PATH")
    if args.max_response_bytes < 1:
        ap.error("--max-response-bytes must be greater than zero")
    
    print(f"Found {len(seed_urls)} seed URL(s):")
    for url in seed_urls[:5]:  # Show first 5
        print(f"  - {url}")
    if len(seed_urls) > 5:
        print(f"  ... and {len(seed_urls) - 5} more")
    print()

    try:
        run_id = _validate_run_id(args.run_id) if args.run_id.strip() else now_run_id()
    except ValueError as exc:
        ap.error(str(exc))
    run_dir = os.path.join(base_dir, "data", "runs", run_id)
    safe_mkdir(run_dir)

    user_agents = load_lines(os.path.join(base_dir, args.ua))
    proxies = load_lines(args.proxies) if args.proxies else []
    proxy_pool = ProxyPool(proxies) if proxies else None

    fetcher = AsyncFetcher(
        user_agents=user_agents,
        proxy_pool=proxy_pool,
        timeout_s=20.0,
        min_delay_s=0.2,
        max_delay_s=1.2,
        retries=2,
        max_response_bytes=args.max_response_bytes,
    )

    extractor = Extractor()
    hunt_terms = [t.strip() for t in (args.hunt.split(",") if args.hunt else []) if t.strip()]

    crawler = AsyncCrawler(
        seed_urls=seed_urls,
        max_depth=args.depth,
        max_urls=args.max,
        run_dir=run_dir,
        fetcher=fetcher,
        extractor=extractor,
        same_domain_only=args.same_domain,
        resume=True,
        concurrency=args.concurrency,
        per_host_concurrency=args.per_host,
        use_ollama=(not args.no_ollama),
        model_analyze=args.model,
        model_embed=args.embed_model,
        hunt_terms=hunt_terms,
        hunt_max_leads=args.hunt_max,
        prompt_profile=args.prompt_profile
    )

    cross_check_models = [m.strip() for m in args.cross_check.split(",") if m.strip()]

    # Model reachability is checked once, up front, so an unreachable server is visible
    # before the crawl instead of appearing as pages that quietly produced no analysis.
    ollama = None
    model_status = "OFF"
    if not args.no_ollama:
        ollama = OllamaAPI()
        health = ollama.health()
        if not health["reachable"]:
            model_status = "UNREACHABLE (analysis will degrade to deterministic only)"
        elif not ollama.has_model(args.model):
            model_status = f"REACHABLE, model {args.model} NOT FOUND"
        else:
            model_status = "REACHABLE"

    print("")
    print("=" * 80)
    print(f"OSINTai v{__version__.split('.')[0]}")
    print(f"RUN DIR: {run_dir}")
    print(f"SEEDS: {len(seed_urls)} URL(s)")
    if len(seed_urls) == 1:
        print(f"SEED: {seed_urls[0]}")
    else:
        print(f"PRIMARY SEED: {seed_urls[0]}")
        print(f"ADDITIONAL SEEDS: {len(seed_urls) - 1}")
    print(f"DEPTH: {args.depth}  MAX_URLS: {args.max}  SAME_DOMAIN: {args.same_domain}")
    print(f"CONCURRENCY: {args.concurrency}  PER_HOST: {args.per_host}")
    print(f"MAX RESPONSE: {args.max_response_bytes} bytes (HTML/XHTML only)")
    print(f"OLLAMA: {'OFF' if args.no_ollama else args.model}")
    print(f"EMBED:  {'OFF' if args.no_ollama else args.embed_model}")
    print(f"HUNT:   {', '.join(hunt_terms) if hunt_terms else 'OFF'}")
    print(f"OLLAMA STATUS: {model_status}")
    if args.profile != "default":
        print(f"PROFILE: {args.profile}" + (f" ({', '.join(profile_applied)})" if profile_applied else ""))
    if args.prompt_profile != STANDARD:
        print(f"PROMPT PROFILE: {args.prompt_profile}")
    print(f"ANALYSIS: {'OFF' if args.no_analysis else 'ON'}"
          f"  DEEP: {'ON' if args.deep else 'OFF'}"
          f"  CROSS-CHECK: {', '.join(cross_check_models) if cross_check_models else 'OFF'}"
          f"  EVALUATE: {'ON' if args.evaluate else 'OFF'}")
    print("=" * 80)
    print("")

    started_at = time.time()
    out = asyncio.run(crawler.crawl())

    page_scores = _read_jsonl(out["page_scores_jsonl"])
    ranked = rank_pages(page_scores)
    report_path = write_report(run_dir, ranked)

    analysis_report_path = ""
    analysis_output = None
    if not args.no_analysis:
        print("")
        print("-" * 80)
        print("ANALYSIS")
        print("-" * 80)
        options = AnalysisOptions(
            deep=args.deep,
            cross_check_models=cross_check_models,
            evaluate=args.evaluate,
            training_export=args.training_export,
            gap_days=args.gap_days,
            prompt_profile=args.prompt_profile,
            model=args.model,
            use_ollama=(not args.no_ollama),
            experimental_recursive=args.experimental_recursive,
            max_leads_per_kind=args.leads_per_kind,
        )
        try:
            analysis_output = analyze_run(
                run_dir=run_dir,
                options=options,
                ollama=ollama,
                run_id=run_id,
                log=print,
            )
            analysis_report_path = write_analysis_report(
                run_dir,
                analysis_output,
                run_id=run_id,
                scope={
                    "seeds": len(seed_urls),
                    "depth": args.depth,
                    "max urls": args.max,
                    "same domain only": args.same_domain,
                    "analysis model": args.model if not args.no_ollama else "none",
                    "prompt profile": args.prompt_profile,
                },
            )
        except Exception as exc:
            # The crawl is already saved. An analysis failure must not cost the operator it.
            print(f"[FAIL] analysis stage aborted -> {exc}")
            print("       Crawl artifacts are intact and the ranked report was written.")

    # Run manifest: what was asked for, what answered, and where it went.
    write_json(os.path.join(run_dir, "run_manifest.json"), {
        "run_id": run_id,
        "osintai_version": __version__,
        "started_at": started_at,
        "finished_at": time.time(),
        "seed_urls": seed_urls,
        "profile": args.profile,
        "prompt_profile": args.prompt_profile,
        "depth": args.depth,
        "max_urls": args.max,
        "same_domain_only": args.same_domain,
        "concurrency": args.concurrency,
        "per_host": args.per_host,
        "max_response_bytes": args.max_response_bytes,
        "hunt_terms": hunt_terms,
        "ollama_enabled": not args.no_ollama,
        "ollama_status": model_status,
        "analysis_model": args.model,
        "embed_model": args.embed_model,
        "analysis_enabled": not args.no_analysis,
        "deep": args.deep,
        "cross_check_models": cross_check_models,
        "evaluate": args.evaluate,
        "training_export": args.training_export,
        "experimental_recursive": args.experimental_recursive,
        "gap_days": args.gap_days,
        "pages_scored": len(page_scores),
        "analysis_stats": analysis_output.stats if analysis_output else {},
    })

    print("")
    print("DONE.")
    print(f"- URLs:         {out['urls_jsonl']}")
    print(f"- Indicators:   {out['indicators_jsonl']}")
    print(f"- Scores:       {out['page_scores_jsonl']}")
    if os.path.exists(out.get("hunt_jsonl","")):
        print(f"- Hunt:         {out['hunt_jsonl']}")
    print(f"- Graph nodes:  {out['graph_nodes']}")
    print(f"- Graph edges:  {out['graph_edges']}")
    print(f"- Report:       {report_path}")
    if analysis_output is not None:
        artifacts = analysis_output.artifacts
        for label, key in (
            ("Findings", "findings"),
            ("Correlations", "correlations"),
            ("Timeline", "timeline"),
            ("Hypotheses", "hypotheses"),
            ("Leads", "leads"),
            ("Analysis:", "analysis_summary"),
        ):
            if artifacts.get(key):
                print(f"- {label + ':' if not label.endswith(':') else label:<13} {artifacts[key]}")
        if artifacts.get("training_export"):
            print(f"- Training export: {artifacts['training_export']}")
        if analysis_report_path:
            print(f"- Analysis report: {analysis_report_path}")
        stats = analysis_output.stats
        print("")
        print(f"  Entities: {stats.get('entities', 0)}"
              f"  Findings: {stats.get('finding_count', 0)}"
              f"  Hypotheses: {stats.get('hypothesis_count', 0)}"
              f"  Leads: {stats.get('lead_count', 0)}")
    print("")

if __name__ == "__main__":
    main()
