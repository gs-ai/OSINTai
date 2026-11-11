"""Command line entry point for the proxy harvester.

Precedence: built-in defaults < config file < explicit command line flags.
"""

import argparse
import asyncio
import json
import os
import sys
from typing import Dict, List, Optional

from .. import __version__
from ..storage import load_lines
from .classify import AsnTable, classify
from .cycle import CycleConfig, ProxyHarvester
from .export import CLASSIFICATION_NOTICE, export_working_set
from .models import ANONYMITY_RANK, ANONYMOUS
from .parsers import candidates_from_lines
from .sources import (
    Source,
    SourceConfigError,
    default_sources,
    load_config,
    sources_from_config,
)
from .status import StatusRenderer
from .stealth import DEFAULT_USER_AGENTS, StealthConfig
from .store import HarvestStore
from .validate import ValidationConfig, detect_local_ip, validate_all

BANNER = (
    "OSINTai proxy harvester -- public free-proxy discovery and validation.\n"
    "Output is disposable test infrastructure. Read the classification notice "
    "in the export manifest before relying on any 'residential_indicated' label."
)


def _load_user_agents(path: Optional[str], base_dir: str) -> List[str]:
    if not path:
        path = os.path.join(base_dir, "user_agents.txt")
    agents = load_lines(path)
    return agents or list(DEFAULT_USER_AGENTS)


def _section(config: Dict, name: str) -> Dict:
    value = config.get(name) or {}
    if not isinstance(value, dict):
        raise SourceConfigError(f"config section '{name}' must be a mapping")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy-harvester",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"OSINTai {__version__}")
    parser.add_argument("--config", default="", help="JSON (or YAML, with PyYAML) config file")

    scope = parser.add_argument_group("run scope")
    scope.add_argument("--once", action="store_true", help="Run exactly one cycle and exit")
    scope.add_argument("--cycles", type=int, default=0, help="Cycle limit (0 = until signalled)")
    scope.add_argument(
        "--interval-min", type=float, default=19.0,
        help="Lower bound of the cycle interval, minutes (default: 19)",
    )
    scope.add_argument(
        "--interval-max", type=float, default=23.0,
        help="Upper bound of the cycle interval, minutes (default: 23)",
    )
    scope.add_argument(
        "--yield-abort", type=float, default=0.0,
        help="Abort when the pass rate stays under this fraction (0 = never)",
    )
    scope.add_argument(
        "--yield-abort-cycles", type=int, default=3,
        help="Consecutive low-yield cycles required to abort (default: 3)",
    )

    io_group = parser.add_argument_group("storage and export")
    io_group.add_argument("--db", default="data/proxies/harvest.sqlite", help="SQLite state file")
    io_group.add_argument("--export-dir", default="data/proxies", help="Export directory")
    io_group.add_argument(
        "--formats", default="csv,json,txt",
        help="Comma-separated export formats: csv, json, jsonl, txt",
    )
    io_group.add_argument(
        "--export-every", type=int, default=1,
        help="Export after every N cycles (default: 1)",
    )

    validation = parser.add_argument_group("validation")
    validation.add_argument("--concurrency", type=int, default=60, help="Concurrent probes")
    validation.add_argument("--timeout", type=float, default=8.0, help="Probe timeout, seconds")
    validation.add_argument(
        "--max-latency", type=float, default=6000.0, help="Latency ceiling, milliseconds"
    )
    validation.add_argument(
        "--min-anonymity", default=ANONYMOUS, choices=sorted(ANONYMITY_RANK),
        help=f"Minimum anonymity grade to admit (default: {ANONYMOUS})",
    )
    validation.add_argument(
        "--no-confirm", action="store_true",
        help="Skip the second confirmation probe (faster, more false positives)",
    )
    validation.add_argument(
        "--echo-url", action="append", default=[],
        help="Echo endpoint returning JSON with headers/origin; repeatable",
    )
    validation.add_argument(
        "--no-revalidate", action="store_true",
        help="Do not re-probe the existing working set each cycle",
    )
    validation.add_argument(
        "--retire-after", type=int, default=3,
        help="Consecutive failures before a proxy leaves W (default: 3)",
    )

    classification = parser.add_argument_group("classification")
    classification.add_argument(
        "--asn-table", default="",
        help="CSV/TSV of 'cidr,asn,org,country' for ASN-based classification",
    )
    classification.add_argument(
        "--no-ptr", action="store_true", help="Skip reverse-DNS lookups"
    )

    fetching = parser.add_argument_group("fetching")
    fetching.add_argument("--ua", default="", help="User-agent file (default: user_agents.txt)")
    fetching.add_argument("--min-delay", type=float, default=1.5, help="Min inter-source delay, s")
    fetching.add_argument("--max-delay", type=float, default=4.5, help="Max inter-source delay, s")
    fetching.add_argument(
        "--enable-js", action="store_true",
        help="Allow the Playwright rendering path for JS-driven sources",
    )
    fetching.add_argument(
        "--ignore-robots", action="store_true",
        help="Do not consult robots.txt (operator assumes responsibility)",
    )
    fetching.add_argument(
        "--allow-chaining", action="store_true",
        help="Route harvest traffic through validated proxies from W (see docs)",
    )
    fetching.add_argument(
        "--no-tls-rotation", action="store_true",
        help="Disable cipher-order variation (verification is always on)",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--json-status", action="store_true", help="Emit JSON status lines")
    output.add_argument("--quiet", action="store_true", help="Suppress status output")

    modes = parser.add_argument_group("alternate modes")
    modes.add_argument("--list-sources", action="store_true", help="Print sources and exit")
    modes.add_argument(
        "--dry-run", action="store_true",
        help="Harvest and parse one cycle without validating",
    )
    modes.add_argument(
        "--validate-file", default="",
        help="Validate an existing ip:port list instead of harvesting",
    )
    modes.add_argument("--stats", action="store_true", help="Print store statistics and exit")

    return parser


def resolve_sources(args, config: Dict) -> List[Source]:
    try:
        return sources_from_config(config)
    except SourceConfigError as exc:
        raise SystemExit(f"config error: {exc}") from exc


def build_validation_config(args, config: Dict) -> ValidationConfig:
    section = _section(config, "validation")
    echo_urls = args.echo_url or section.get("echo_urls") or None
    kwargs = {
        "timeout_s": args.timeout,
        "max_latency_ms": args.max_latency,
        "concurrency": args.concurrency,
        "min_anonymity": args.min_anonymity,
        "confirm": not args.no_confirm,
    }
    for key in ("connect_timeout_s", "confirm_delay_s", "max_body_bytes", "verify_tls"):
        if key in section:
            kwargs[key] = section[key]
    if echo_urls:
        kwargs["echo_urls"] = tuple(echo_urls)
    return ValidationConfig(**kwargs)


def build_stealth_config(args, config: Dict, base_dir: str) -> StealthConfig:
    section = _section(config, "stealth")
    return StealthConfig(
        user_agents=_load_user_agents(args.ua or section.get("user_agents_file"), base_dir),
        min_delay_s=args.min_delay,
        max_delay_s=args.max_delay,
        randomize_tls_order=not args.no_tls_rotation,
        allow_chaining=args.allow_chaining or bool(section.get("allow_chaining")),
        chain_min_anonymity=section.get("chain_min_anonymity", "elite"),
        chain_max_age_s=float(section.get("chain_max_age_s", 900.0)),
    )


def build_cycle_config(args, config: Dict) -> CycleConfig:
    section = _section(config, "cycle")
    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    unknown = set(formats) - {"csv", "json", "jsonl", "txt"}
    if unknown:
        raise SystemExit(f"unknown export format(s): {sorted(unknown)}")

    return CycleConfig(
        interval_min_s=args.interval_min * 60.0,
        interval_max_s=args.interval_max * 60.0,
        max_cycles=1 if args.once else args.cycles,
        export_every_cycles=args.export_every,
        export_formats=formats,
        export_dir=args.export_dir,
        revalidate_working_set=not args.no_revalidate,
        retire_after_failures=args.retire_after,
        max_candidates_per_cycle=int(section.get("max_candidates_per_cycle", 4000)),
        yield_abort_threshold=args.yield_abort,
        yield_abort_cycles=args.yield_abort_cycles,
        allow_js=args.enable_js,
        respect_robots=not args.ignore_robots,
        resolve_ptr=not args.no_ptr,
        asn_table_path=args.asn_table or section.get("asn_table") or None,
    )


async def run_validate_file(args, config: Dict, renderer: StatusRenderer) -> int:
    """One-shot validation of an operator-supplied list."""
    path = os.path.abspath(os.path.expanduser(args.validate_file))
    if not os.path.isfile(path):
        renderer.message(f"[ERROR] list not found: {path}")
        return 2

    candidates = candidates_from_lines(load_lines(path), source_id="file")
    if not candidates:
        renderer.message(f"[ERROR] no usable ip:port entries parsed from {path}")
        return 2
    renderer.message(f"[validate-file] {len(candidates)} candidates from {path}")

    validation = build_validation_config(args, config)
    local_ip = await detect_local_ip(validation, verify=validation.verify_tls)

    def progress(done: int, total: int) -> None:
        if done % 25 == 0 or done == total:
            renderer.message(f"[validate-file] {done}/{total}")

    report = await validate_all(candidates, validation, local_ip, progress=progress)

    asn_table = None
    if args.asn_table:
        try:
            asn_table = AsnTable.load(args.asn_table)
        except (OSError, ValueError) as exc:
            renderer.message(f"[WARN] ASN table unavailable: {exc}")

    rows = []
    for result in report.passed:
        classification = classify(
            result.exit_ip or result.candidate.ip,
            asn_table=asn_table,
            resolve_ptr=not args.no_ptr,
        )
        rows.append(
            {
                "key": result.candidate.key,
                "ip": result.candidate.ip,
                "port": result.candidate.port,
                "protocol": result.candidate.protocol,
                "source_id": "file",
                "latency_ms": round(result.latency_ms or 0.0, 1),
                "anonymity": result.anonymity,
                "exit_ip": result.exit_ip,
                "network_class": classification.network_class,
                "classification_confidence": round(classification.confidence, 2),
                "classification_basis": "; ".join(classification.basis),
                "asn": classification.asn,
                "as_org": classification.as_org,
                "country": classification.country,
                "ptr": classification.ptr,
                "ok_count": 1,
                "fail_count": 0,
            }
        )

    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    result = export_working_set(
        args.export_dir, rows, formats=formats,
        context={"mode": "validate-file", "input": path, "attempted": report.attempted},
    )
    renderer.message(
        f"[validate-file] passed {len(report.passed)}/{report.attempted} "
        f"({report.yield_rate * 100:.1f}%) -> {result.directory}"
    )
    if report.skipped:
        renderer.message(f"[validate-file] skipped {len(report.skipped)} (unsupported protocol)")
    return 0


async def run_dry_run(args, sources: List[Source], config: Dict, renderer: StatusRenderer) -> int:
    """Harvest and parse without probing anything."""
    from .harvest import harvest_all, merge_candidates

    base_dir = _base_dir()
    rotator_config = build_stealth_config(args, config, base_dir)
    from .stealth import StealthRotator

    rotator = StealthRotator(rotator_config)
    results = await harvest_all(
        sources, rotator,
        allow_js=args.enable_js,
        respect_robots=not args.ignore_robots,
    )
    for result in results:
        status = "ok" if result.ok else "FAIL"
        note = result.error or result.skipped_reason or ""
        renderer.message(
            f"[{status:>4}] {result.source_id:<20} renderer={result.renderer:<6} "
            f"kind={result.kind:<5} candidates={len(result.candidates):<6} "
            f"{result.elapsed_ms:.0f}ms {note}"
        )
    merged = merge_candidates(results)
    renderer.message(f"[dry-run] {len(merged)} unique candidates across {len(results)} sources")
    renderer.message("[dry-run] no probes were sent; nothing was validated or exported")
    return 0


def _base_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))


async def run_async(args) -> int:
    renderer = StatusRenderer(json_mode=args.json_status, quiet=args.quiet)
    base_dir = _base_dir()

    try:
        config = load_config(args.config) if args.config else {}
    except SourceConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    sources = resolve_sources(args, config)

    if args.list_sources:
        print(json.dumps([s.to_row() for s in sources], indent=2))
        return 0

    if args.stats:
        with HarvestStore(args.db) as store:
            print(store.dump_json())
        return 0

    if args.validate_file:
        return await run_validate_file(args, config, renderer)

    if args.dry_run:
        return await run_dry_run(args, sources, config, renderer)

    renderer.message(BANNER)
    cycle_config = build_cycle_config(args, config)
    validation_config = build_validation_config(args, config)
    stealth_config = build_stealth_config(args, config, base_dir)

    with HarvestStore(args.db) as store:
        harvester = ProxyHarvester(
            sources=sources,
            store=store,
            cycle_config=cycle_config,
            validation_config=validation_config,
            stealth_config=stealth_config,
            renderer=renderer,
        )
        summary = await harvester.run()

    renderer.message(
        f"[done] cycles={summary['cycles']} |W|={summary['working_size']} "
        f"{'(' + summary['aborted_reason'] + ')' if summary['aborted_reason'] else ''}"
    )
    renderer.message(f"[notice] {CLASSIFICATION_NOTICE}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.interval_min <= 0 or args.interval_max <= 0:
        parser.error("--interval-min and --interval-max must be positive")
    if args.interval_max < args.interval_min:
        parser.error("--interval-max must be >= --interval-min")
    if args.cycles < 0:
        parser.error("--cycles must be >= 0")
    if not 0.0 <= args.yield_abort <= 1.0:
        parser.error("--yield-abort must be a fraction between 0 and 1")
    if args.concurrency < 1:
        parser.error("--concurrency must be >= 1")

    try:
        return asyncio.run(run_async(args))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
