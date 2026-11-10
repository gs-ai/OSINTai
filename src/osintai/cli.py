import os
import sys
import argparse
import json
import asyncio
import re
import time
import tempfile
import math
from urllib.parse import urlparse

from osintai.storage import safe_mkdir, now_run_id, load_lines, write_json, read_json
from osintai.extractor import Extractor
from osintai.proxy_pool import ProxyPool
from osintai.fetcher import AsyncFetcher
from osintai.crawler import AsyncCrawler, UNLIMITED_DEPTH
from osintai.scoring import rank_pages
from osintai.report import write_report
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

MIN_RUNTIME_MIN, MAX_RUNTIME_MIN = 1, 360
# Safety ceilings applied to timed expansion unless the operator states otherwise.
EXPAND_DEFAULTS = {"max": 50_000, "max_per_host": 500}


def _flag_given(argv: list[str], flag: str) -> bool:
    return any(arg == flag or arg.startswith(flag + "=") for arg in argv)


def _parse_runtime(value) -> float:
    """Runtime in minutes, restricted to the supported 1-360 window."""
    try:
        minutes = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"runtime must be a number of minutes, got {value!r}") from None
    if not math.isfinite(minutes) or not MIN_RUNTIME_MIN <= minutes <= MAX_RUNTIME_MIN:
        raise ValueError(
            f"runtime must be between {MIN_RUNTIME_MIN} and {MAX_RUNTIME_MIN} minutes"
        )
    return minutes


def _prompt_start_url(input_fn=input, attempts: int = 5) -> str:
    for _ in range(attempts):
        value = input_fn("Starting URL: ").strip()
        if value and "://" not in value:
            value = "https://" + value
        if _valid_seed_url(value):
            return value
        print("  Enter a full HTTP(S) URL, e.g. https://example.com/")
    raise ValueError("no valid starting URL was provided")


def _prompt_runtime(input_fn=input, attempts: int = 5) -> float:
    for _ in range(attempts):
        try:
            return _parse_runtime(input_fn(
                f"Runtime in minutes ({MIN_RUNTIME_MIN}-{MAX_RUNTIME_MIN}): ").strip())
        except ValueError as exc:
            print(f"  {exc}")
    raise ValueError("no valid runtime was provided")


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

def _analyze_saved_run(args: argparse.Namespace, ap: argparse.ArgumentParser, base_dir: str) -> None:
    """Recover offline into a unique directory without touching original outputs."""
    try:
        run_id = _validate_run_id(args.analyze_only)
    except ValueError as exc:
        ap.error(str(exc))
    source = os.path.realpath(os.path.join(base_dir, "data", "runs", run_id))
    runs_root = os.path.realpath(os.path.join(base_dir, "data", "runs"))
    if os.path.commonpath([source, runs_root]) != runs_root:
        ap.error("saved run must remain inside data/runs")
    if not os.path.isfile(os.path.join(source, "urls_crawled.jsonl")):
        ap.error(f"No saved crawl found in {source}")
    if args.no_analysis or args.deep or args.cross_check or args.experimental_recursive:
        ap.error("--analyze-only is offline; incompatible with --no-analysis or model-assisted modes")
    destination = tempfile.mkdtemp(prefix="reanalysis_", dir=source)
    print(f"OSINTai {__version__}: offline analysis of {run_id}", flush=True)
    print(f"RESULTS: {destination}", flush=True)
    output = analyze_run(
        source,
        AnalysisOptions(
            use_ollama=False, evaluate=args.evaluate, training_export=args.training_export,
            gap_days=args.gap_days, max_leads_per_kind=args.leads_per_kind,
            max_text_chars=args.analysis_max_chars,
            page_deadline_s=getattr(args, 'analysis_page_timeout', 30.0),
            stage_deadline_s=getattr(args, 'analysis_stage_timeout', 120.0),
            candidate_pair_budget=getattr(args, 'correlation_pair_budget', 100_000),
            text_cache_bytes=getattr(args, 'text_cache_bytes', 16_000_000),
        ),
        run_id=run_id, output_dir=destination,
        log=lambda message: print(message, flush=True),
    )
    print(f"DONE. Analysis report: {output.artifacts['analysis_report']}", flush=True)



def main():
    try:
        _main()
    except KeyboardInterrupt:
        print("\nInterrupted. Saved crawl files and the unfinished frontier are retained. "
              "Continue with --resume RUN_ID or analyze with --analyze-only RUN_ID.",
              file=sys.stderr, flush=True)
        raise SystemExit(130)


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Aligned two-column help that wraps to the terminal, capped for readability."""

    def __init__(self, prog):
        import shutil
        width = min(shutil.get_terminal_size((100, 24)).columns, 100) - 2
        super().__init__(prog, max_help_position=34, width=width)

    def _format_action_invocation(self, action):
        # "--seed URL" instead of the default "--seed SEED".
        if not action.option_strings or action.nargs == 0:
            return super()._format_action_invocation(action)
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return ", ".join(action.option_strings) + " " + metavar


_HELP_EPILOG = """\
examples:
  Crawl one site and analyze it
    %(prog)s --seed https://example.com --same-domain

  Timed recursive expansion for 30 minutes
    %(prog)s --expand --seed https://example.com --runtime 30

  Continue an interrupted run, or re-analyze one offline
    %(prog)s --resume RUN_ID
    %(prog)s --analyze-only RUN_ID

  Crawl and report only, no local LLM
    %(prog)s --seed-file seeds.txt --no-ollama --no-analysis

Runs are saved under data/runs/RUN_ID/.
"""


def _build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog=os.path.basename(sys.argv[0]) or "osintai",
        usage="%(prog)s [--seed URL | --seed-file PATH | --resume RUN_ID] [options]",
        description=f"OSINTai {__version__} - async OSINT crawling and local-LLM analysis",
        epilog=_HELP_EPILOG,
        formatter_class=_HelpFormatter,
        add_help=False,
    )

    general = ap.add_argument_group("general")
    general.add_argument("-h", "--help", action="help", help="Show this help and exit")
    general.add_argument("--version", action="version", version=f"OSINTai {__version__}",
                         help="Show version and exit")

    target = ap.add_argument_group("target")
    target.add_argument("--seed", action="append", metavar="URL",
                        help="Seed HTTP(S) URL (repeatable)")
    target.add_argument("--seed-file", metavar="PATH",
                        help="File with one HTTP(S) seed URL per line")
    target.add_argument("--profile", default="default", choices=sorted(RUN_PROFILES),
                        metavar="NAME",
                        help=f"Run preset: {' | '.join(sorted(RUN_PROFILES))} (default: default)")
    target.add_argument("--run-id", default="", metavar="ID",
                        help="Override the generated run ID")

    modes = ap.add_argument_group("run modes")
    modes.add_argument("--expand", action="store_true",
                       help="Timed recursive expansion; prompts for URL and runtime "
                            "unless --seed and --runtime are given")
    modes.add_argument("--runtime", metavar="MINUTES",
                       help=f"Stop after {MIN_RUNTIME_MIN}-{MAX_RUNTIME_MIN} minutes and "
                            "checkpoint the frontier; implies unlimited depth "
                            "unless --depth is set")
    modes.add_argument("--resume", metavar="RUN_ID",
                       help="Continue a saved run from its checkpoint")
    modes.add_argument("--analyze-only", metavar="RUN_ID",
                       help="Re-analyze a saved run offline (no crawling, no LLM)")
    modes.add_argument("--retry-model", metavar="RUN_ID",
                       help="Retry failed/missing model responses for a saved run")

    scope = ap.add_argument_group("crawl scope")
    scope.add_argument("--depth", type=int, default=2, metavar="N",
                       help="Maximum link depth (default: 2)")
    scope.add_argument("--max", type=int, default=150, metavar="N",
                       help="Maximum URLs to crawl (default: 150)")
    scope.add_argument("--same-domain", action="store_true",
                       help="Stay on the seed's domain")
    scope.add_argument("--max-frontier", type=int, default=50_000, metavar="N",
                       help="Maximum queued URLs held at once (default: 50,000)")
    scope.add_argument("--max-per-host", type=int, default=0, metavar="N",
                       help="Maximum requests per host, 0 = unlimited "
                            "(default: 0; 500 with --runtime)")

    network = ap.add_argument_group("network")
    network.add_argument("--concurrency", type=int, default=18, metavar="N",
                         help="Global concurrent requests (default: 18)")
    network.add_argument("--per-host", type=int, default=4, metavar="N",
                         help="Concurrent requests per host (default: 4)")
    network.add_argument("--max-response-bytes", type=int, default=2_000_000, metavar="BYTES",
                         help="Maximum decoded HTML response size (default: 2,000,000)")
    network.add_argument("--ua", default="user_agents.txt", metavar="PATH",
                         help="User-agent list file (default: user_agents.txt)")
    network.add_argument("--proxies", default="", metavar="PATH",
                         help="Proxy list file (optional)")

    hunt = ap.add_argument_group("hunt mode")
    hunt.add_argument("--hunt", default="", metavar="TERMS",
                      help="Comma-separated terms to prioritize links by")
    hunt.add_argument("--hunt-max", type=int, default=50, metavar="N",
                      help="Maximum lead URLs per page (default: 50)")

    models = ap.add_argument_group("models (ollama)")
    models.add_argument("--model", default="osint-tuned-v3:latest", metavar="NAME",
                        help="Analysis model (default: osint-tuned-v3:latest)")
    models.add_argument("--embed-model", default="bge-m3:latest", metavar="NAME",
                        help="Embeddings model (default: bge-m3:latest)")
    models.add_argument("--no-ollama", action="store_true",
                        help="Disable LLM analysis and embeddings")
    models.add_argument("--prompt-profile", default=STANDARD, choices=sorted(PAGE_PROFILES),
                        metavar="LENS",
                        help=f"Page analysis lens: {' | '.join(sorted(PAGE_PROFILES))} "
                             f"(default: {STANDARD})")

    analysis = ap.add_argument_group("analysis")
    analysis.add_argument("--no-analysis", action="store_true",
                          help="Skip post-crawl analysis (crawl and report only)")
    analysis.add_argument("--deep", action="store_true",
                          help="Add a model-assisted run-level analysis pass")
    analysis.add_argument("--cross-check", default="", metavar="MODELS",
                          help="Comma-separated extra models to cross-check claims")
    analysis.add_argument("--evaluate", action="store_true",
                          help="Score analysis against the investigative rubric")
    analysis.add_argument("--training-export", action="store_true",
                          help="Export training/evaluation datasets (needs --evaluate)")
    analysis.add_argument("--gap-days", type=int, default=90, metavar="DAYS",
                          help="Temporal gap threshold (default: 90)")
    analysis.add_argument("--leads-per-kind", type=int, default=10, metavar="N",
                          help="Entities per kind expanded into pivot leads (default: 10)")
    analysis.add_argument("--experimental-recursive", type=int, default=0, metavar="N",
                          help="EXPERIMENTAL: extra deep-analysis passes, 0-3 (default: 0)")

    retry = ap.add_argument_group("model retry (with --retry-model)")
    retry.add_argument("--retry-limit", type=int, default=20, metavar="N",
                       help="Maximum saved pages retried (default: 20)")
    retry.add_argument("--retry-timeout", type=float, default=60.0, metavar="SECS",
                       help="Deadline per model retry (default: 60)")

    tuning = ap.add_argument_group("advanced tuning")
    tuning.add_argument("--analysis-max-chars", type=int, default=200_000, metavar="N",
                        help="Characters analyzed per page (default: 200,000)")
    tuning.add_argument("--analysis-page-timeout", type=float, default=30.0, metavar="SECS",
                        help="Extraction worker deadline per page (default: 30)")
    tuning.add_argument("--analysis-stage-timeout", type=float, default=120.0, metavar="SECS",
                        help="Analysis stage deadline (default: 120)")
    tuning.add_argument("--correlation-pair-budget", type=int, default=100_000, metavar="N",
                        help="Co-occurrence candidate pairs examined (default: 100,000)")
    tuning.add_argument("--text-cache-bytes", type=int, default=16_000_000, metavar="BYTES",
                        help="Page-text LRU cache per process (default: 16,000,000)")
    return ap


def _main():
    ap = _build_parser()

    argv = list(sys.argv[1:])
    args = ap.parse_args()

    # A profile supplies values the operator did not state. An explicit flag always wins.
    profile_values = RUN_PROFILES.get(args.profile, {})
    profile_applied = []
    for dest, value in profile_values.items():
        flag = "--" + dest.replace("_", "-")
        if any(arg == flag or arg.startswith(flag + "=") for arg in argv):
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

    for flag, value in (("analysis-max-chars", args.analysis_max_chars),
                        ("retry-limit", args.retry_limit), ("retry-timeout", args.retry_timeout),
                        ("analysis-page-timeout", args.analysis_page_timeout),
                        ("analysis-stage-timeout", args.analysis_stage_timeout),
                        ("correlation-pair-budget", args.correlation_pair_budget),
                        ("text-cache-bytes", args.text_cache_bytes),
                        ("concurrency", args.concurrency), ("per-host", args.per_host),
                        ("max", args.max), ("hunt-max", args.hunt_max),
                        ("max-frontier", args.max_frontier),
                        ("leads-per-kind", args.leads_per_kind)):
        if not math.isfinite(value) or value <= 0:
            ap.error(f"--{flag} must be finite and greater than zero")
    if args.depth < 0:
        ap.error("--depth must be nonnegative")
    if args.max_per_host < 0:
        ap.error("--max-per-host must be nonnegative")
    if args.retry_model:
        if args.analyze_only or args.no_ollama:
            ap.error("--retry-model requires Ollama and cannot be combined with --analyze-only")
        from .model_retry import retry_saved
        try:
            saved_id = _validate_run_id(args.retry_model)
        except ValueError as exc:
            ap.error(str(exc))
        runs = os.path.realpath(os.path.join(base_dir, "data", "runs"))
        source = os.path.realpath(os.path.join(runs, saved_id))
        if os.path.commonpath([runs, source]) != runs or not os.path.isfile(os.path.join(source, "urls_crawled.jsonl")):
            ap.error("No saved crawl found inside data/runs")
        result = asyncio.run(retry_saved(source, OllamaAPI(), args.model, args.retry_limit,
            args.retry_timeout, args.analysis_max_chars, args.prompt_profile))
        print(f"DONE. Saved model retry results: {result}")
        return
    if args.analyze_only:
        return _analyze_saved_run(args, ap, base_dir)

    runs_root = os.path.join(base_dir, "data", "runs")
    resumed_seeds: list[str] = []
    if args.resume:
        try:
            args.run_id = _validate_run_id(args.resume)
        except ValueError as exc:
            ap.error(str(exc))
        saved = read_json(os.path.join(runs_root, args.run_id, "crawl_state.json"), default=None)
        if not saved:
            ap.error(f"No resumable crawl state found for run {args.run_id!r}")
        resumed_seeds = [u for u in saved.get("seed_urls", []) if _valid_seed_url(u)]

    try:
        seed_urls = _resolve_seed_urls(args.seed, args.seed_file, base_dir)
        if resumed_seeds and not (args.seed or args.seed_file):
            seed_urls = resumed_seeds
        interactive = args.expand or (not seed_urls and sys.stdin.isatty())
        if not seed_urls and interactive:
            seed_urls = [_prompt_start_url()]
        runtime_min = _parse_runtime(args.runtime) if args.runtime is not None else None
        if runtime_min is None and interactive:
            runtime_min = _prompt_runtime()
    except EOFError:
        ap.error("--expand needs --seed and --runtime when input is not interactive")
    except (OSError, ValueError) as exc:
        ap.error(str(exc))
    if not seed_urls:
        ap.error("No seed URLs found. Provide --seed URL or --seed-file PATH")

    if runtime_min is not None:
        # Timed expansion runs until the clock or the frontier ends, not a depth limit.
        if not _flag_given(argv, "--depth") and "depth" not in profile_values:
            args.depth = UNLIMITED_DEPTH
        for dest, value in EXPAND_DEFAULTS.items():
            if not _flag_given(argv, "--" + dest.replace("_", "-")) and dest not in profile_values:
                setattr(args, dest, value)
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
    run_dir = os.path.join(runs_root, run_id)
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
        prompt_profile=args.prompt_profile,
        extraction_timeout_s=args.analysis_page_timeout,
        runtime_s=runtime_min * 60 if runtime_min is not None else None,
        max_frontier=args.max_frontier,
        max_per_host=args.max_per_host,
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
    print(f"OSINTai {__version__}")
    print(f"RUN DIR: {run_dir}")
    print(f"SEEDS: {len(seed_urls)} URL(s)")
    if len(seed_urls) == 1:
        print(f"SEED: {seed_urls[0]}")
    else:
        print(f"PRIMARY SEED: {seed_urls[0]}")
        print(f"ADDITIONAL SEEDS: {len(seed_urls) - 1}")
    depth_label = "unlimited" if args.depth >= UNLIMITED_DEPTH else args.depth
    print(f"DEPTH: {depth_label}  MAX_URLS: {args.max}  SAME_DOMAIN: {args.same_domain}")
    if runtime_min is not None:
        print(f"RUNTIME: {runtime_min:g} min  MAX_FRONTIER: {args.max_frontier}"
              f"  MAX_PER_HOST: {args.max_per_host or 'unlimited'}")
    if args.resume:
        print(f"RESUMING: {len(crawler.visited)} URL(s) done, {len(crawler.queued)} queued")
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
            max_text_chars=args.analysis_max_chars,
            page_deadline_s=args.analysis_page_timeout,
            stage_deadline_s=args.analysis_stage_timeout,
            candidate_pair_budget=args.correlation_pair_budget,
            text_cache_bytes=args.text_cache_bytes,
        )
        try:
            analysis_output = analyze_run(
                run_dir=run_dir,
                options=options,
                ollama=ollama,
                run_id=run_id,
                log=lambda message: print(message, flush=True),
            )
            analysis_report_path = analysis_output.artifacts["analysis_report"]
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
        "runtime_minutes": runtime_min,
        "max_frontier": args.max_frontier,
        "max_per_host": args.max_per_host,
        "resumed": bool(args.resume),
        "stop_reason": out["stop_reason"],
        "frontier_remaining": out["frontier_remaining"],
        "crawl_stats": {k: v for k, v in out["stats"].items() if k != "rounds"},
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
        "model_responses": analysis_output.stats.get("model_responses", {}) if analysis_output else {},
        "model_call_counts": crawler.ollama.response_counts if crawler.ollama else {},
        "analysis_bundle": analysis_output.artifacts.get("run_manifest") if analysis_output else None,
        "analysis_stats": analysis_output.stats if analysis_output else {},
    })

    print("")
    print("DONE.")
    print(f"- URLs:         {out['urls_jsonl']}")
    print(f"- Indicators:   {out['indicators_jsonl']}")
    print(f"- Scores:       {out['page_scores_jsonl']}")
    if os.path.exists(out.get("hunt_jsonl","")):
        print(f"- Hunt:         {out['hunt_jsonl']}")
    print(f"- Discovery:    {out['discovery_edges']}")
    print(f"- Crawl stats:  {out['crawl_stats']}")
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
    if out["frontier_remaining"]:
        print("")
        print(f"  Stopped: {out['stop_reason']}. {out['frontier_remaining']} URL(s) remain queued.")
        print(f"  Continue with: --resume {run_id} --runtime MINUTES")
    print("")

if __name__ == "__main__":
    main()
