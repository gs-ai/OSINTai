"""Cycle orchestration: harvest, validate, classify, persist, export, wait.

One cycle is:

  sample T ~ U[interval_min, interval_max]
  -> fetch every enabled source (language-dispatched)
  -> parse and de-duplicate candidates
  -> re-validate the current working set, then validate new candidates
  -> classify passing exits from ASN/PTR evidence
  -> update W, record metrics
  -> export at the configured checkpoint
  -> sleep the remainder of T, interruptibly

The loop terminates on SIGINT/SIGTERM, on a cycle limit, or when the measured
yield stays under the abort threshold for the configured number of cycles.
"""

import asyncio
import secrets
import signal
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .classify import AsnTable, classify
from .export import export_working_set
from .harvest import harvest_all, merge_candidates, playwright_available
from .models import ProxyCandidate
from .parsers import dedupe
from .sources import Source, enabled_sources
from .status import (
    HarvesterState,
    PHASE_CLASSIFY,
    PHASE_EXPORT,
    PHASE_HARVEST,
    PHASE_PARSE,
    PHASE_STOPPING,
    PHASE_VALIDATE,
    PHASE_WAIT,
    StatusRenderer,
)
from .stealth import StealthConfig, StealthRotator
from .store import HarvestStore
from .validate import ValidationConfig, detect_local_ip, validate_all

_RANDOM = secrets.SystemRandom()


@dataclass
class CycleConfig:
    """Loop-level policy."""

    interval_min_s: float = 19 * 60.0
    interval_max_s: float = 23 * 60.0
    max_cycles: int = 0                 # 0 = run until signalled
    export_every_cycles: int = 1
    export_formats: List[str] = field(default_factory=lambda: ["csv", "json", "txt"])
    export_dir: str = "data/proxies"
    revalidate_working_set: bool = True
    retire_after_failures: int = 3
    max_candidates_per_cycle: int = 4000
    yield_abort_threshold: float = 0.0  # 0 = never abort on low yield
    yield_abort_cycles: int = 3
    allow_js: bool = False
    respect_robots: bool = True
    resolve_ptr: bool = True
    asn_table_path: Optional[str] = None

    def __post_init__(self):
        if self.interval_max_s < self.interval_min_s:
            self.interval_max_s = self.interval_min_s
        if self.export_every_cycles < 1:
            self.export_every_cycles = 1


class ProxyHarvester:
    """Owns the cycle loop and all long-lived state."""

    def __init__(
        self,
        sources: List[Source],
        store: HarvestStore,
        cycle_config: Optional[CycleConfig] = None,
        validation_config: Optional[ValidationConfig] = None,
        stealth_config: Optional[StealthConfig] = None,
        renderer: Optional[StatusRenderer] = None,
    ):
        self.sources = enabled_sources(sources)
        self.store = store
        self.config = cycle_config or CycleConfig()
        self.validation = validation_config or ValidationConfig()
        self.rotator = StealthRotator(stealth_config or StealthConfig())
        self.renderer = renderer or StatusRenderer()
        self.state = HarvesterState()
        self.stop_event = asyncio.Event()
        self.local_ip: Optional[str] = None
        self.asn_table: Optional[AsnTable] = None
        self._low_yield_streak = 0
        self._cycles_run = 0

    # ---- lifecycle -----------------------------------------------------
    def install_signal_handlers(self) -> None:
        """Ask the loop to stop at the next checkpoint rather than killing it.

        A hard kill mid-validation loses the cycle's results; a cooperative stop
        finishes the current phase and writes a final export.
        """
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, self._request_stop, sig)
            except (NotImplementedError, RuntimeError, ValueError):
                # Windows and non-main threads: fall back to KeyboardInterrupt.
                pass

    def _request_stop(self, sig) -> None:
        if self.stop_event.is_set():
            return
        self.renderer.message(
            f"\n[signal {getattr(sig, 'name', sig)}] finishing current phase, then exporting."
        )
        self.state.phase = PHASE_STOPPING
        self.stop_event.set()

    def load_asn_table(self) -> None:
        if not self.config.asn_table_path:
            return
        try:
            self.asn_table = AsnTable.load(self.config.asn_table_path)
            self.renderer.message(
                f"[asn] loaded {len(self.asn_table)} prefixes from {self.config.asn_table_path}"
            )
        except (OSError, ValueError) as exc:
            self.renderer.message(f"[WARN] ASN table unavailable ({exc}); "
                                  "classification will rely on PTR evidence only")
            self.asn_table = None

    # ---- one cycle -----------------------------------------------------
    def sample_interval(self) -> float:
        return _RANDOM.uniform(self.config.interval_min_s, self.config.interval_max_s)

    async def run_cycle(self, cycle_number: int) -> Dict:
        interval = self.sample_interval()
        cycle_id = self.store.start_cycle(interval)

        self.state.cycle = cycle_number
        self.state.interval_s = interval
        self.state.cycle_started_at = time.time()
        self.state.candidates = 0
        self.state.validated = 0
        self.state.passed = 0
        self.state.yield_rate = 0.0

        # --- harvest ---
        self.state.phase = PHASE_HARVEST
        self.state.detail = ""
        self.renderer.render(self.state)

        def on_source(done: int, total: int, result) -> None:
            self.state.progress = f"src {done}/{total}"
            self.state.detail = f"{result.source_id}:{len(result.candidates)}"
            self.renderer.render(self.state)

        harvest_results = await harvest_all(
            self.sources,
            self.rotator,
            allow_js=self.config.allow_js,
            respect_robots=self.config.respect_robots,
            verify=self.validation.verify_tls,
            progress=on_source,
        )
        self.store.record_source_stats(cycle_id, harvest_results)
        sources_ok = sum(1 for r in harvest_results if r.ok)
        sources_failed = len(harvest_results) - sources_ok
        for result in harvest_results:
            if result.error or result.skipped_reason:
                self.renderer.message(
                    f"[source] {result.source_id}: {result.error or result.skipped_reason}"
                )

        # --- parse ---
        self.state.phase = PHASE_PARSE
        self.state.progress = ""
        self.renderer.render(self.state)
        candidates = merge_candidates(harvest_results)
        self.store.record_candidates(candidates)

        # --- assemble the validation batch ---
        batch: List[ProxyCandidate] = []
        working_rows = self.store.working_set()
        if self.config.revalidate_working_set and working_rows:
            batch.extend(
                ProxyCandidate(
                    ip=row["ip"], port=row["port"],
                    protocol=row["protocol"], source_id=row["source_id"] or "",
                )
                for row in working_rows
            )
        batch.extend(candidates)
        batch = dedupe(batch)
        if len(batch) > self.config.max_candidates_per_cycle:
            # Keep the working set (it is at the front) and truncate new candidates.
            batch = batch[: self.config.max_candidates_per_cycle]
        self.state.candidates = len(batch)

        # --- validate ---
        self.state.phase = PHASE_VALIDATE
        self.renderer.render(self.state)

        def on_progress(done: int, total: int) -> None:
            self.state.progress = f"probe {done}/{total}"
            if done % 25 == 0 or done == total:
                self.renderer.render(self.state)

        report = await validate_all(batch, self.validation, self.local_ip, progress=on_progress)
        self.store.record_validations(report.passed + report.failed, cycle_id)
        self.state.validated = report.attempted
        self.state.passed = len(report.passed)
        self.state.yield_rate = report.yield_rate
        self.state.progress = ""

        # --- classify and update W ---
        self.state.phase = PHASE_CLASSIFY
        self.renderer.render(self.state)
        for index, result in enumerate(report.passed):
            classification = classify(
                result.exit_ip or result.candidate.ip,
                asn_table=self.asn_table,
                resolve_ptr=self.config.resolve_ptr,
            )
            self.store.upsert_working(result, classification)
            if index % 20 == 0:
                self.state.progress = f"class {index + 1}/{len(report.passed)}"
                self.renderer.render(self.state)
        self.state.progress = ""

        passed_keys = {r.candidate.key for r in report.passed}
        failed_keys = [
            row["key"] for row in working_rows if row["key"] not in passed_keys
        ]
        retired = self.store.mark_failures(failed_keys, self.config.retire_after_failures)
        if retired:
            self.renderer.message(f"[churn] retired {retired} proxies after repeated failures")

        working = self.store.working_set()
        self.state.working_size = len(working)
        self.rotator.set_working_pool(working)

        self.store.finish_cycle(
            cycle_id,
            sources_ok=sources_ok,
            sources_failed=sources_failed,
            candidates=len(candidates),
            validated=report.attempted,
            passed=len(report.passed),
            yield_rate=report.yield_rate,
            working_size=len(working),
        )

        return {
            "cycle_id": cycle_id,
            "interval_s": interval,
            "sources_ok": sources_ok,
            "sources_failed": sources_failed,
            "candidates": len(candidates),
            "validated": report.attempted,
            "passed": len(report.passed),
            "skipped": len(report.skipped),
            "yield_rate": report.yield_rate,
            "working_size": len(working),
        }

    # ---- export --------------------------------------------------------
    def export(self, context: Optional[Dict] = None) -> Optional[str]:
        self.state.phase = PHASE_EXPORT
        self.renderer.render(self.state)
        rows = self.store.working_set()
        result = export_working_set(
            self.config.export_dir,
            rows,
            formats=self.config.export_formats,
            context=context,
        )
        self.state.last_export = result.stamp
        self.renderer.message(
            f"[export] {result.count} proxies -> {result.directory} (stamp {result.stamp})"
        )
        return result.stamp

    # ---- wait ----------------------------------------------------------
    async def wait_remaining(self) -> None:
        """Sleep the remainder of T, waking early on a stop signal."""
        self.state.phase = PHASE_WAIT
        while not self.stop_event.is_set():
            remaining = self.state.remaining_s
            if remaining <= 0:
                return
            self.renderer.render(self.state)
            try:
                await asyncio.wait_for(self.stop_event.wait(), timeout=min(1.0, remaining))
            except asyncio.TimeoutError:
                continue

    # ---- main loop -----------------------------------------------------
    async def run(self) -> Dict:
        self.install_signal_handlers()
        self.load_asn_table()

        if self.config.allow_js and not playwright_available():
            self.renderer.message(
                "[WARN] --enable-js set but playwright is not installed; "
                "JS sources will be skipped"
            )

        self.local_ip = await detect_local_ip(self.validation, verify=self.validation.verify_tls)
        if self.local_ip:
            self.renderer.message(
                f"[baseline] local egress address detected; leak detection active"
            )
        else:
            self.renderer.message(
                "[WARN] could not determine local egress address; "
                "'transparent' proxies may be graded 'anonymous'"
            )

        summaries: List[Dict] = []
        cycle_number = 0
        aborted_reason = None

        while not self.stop_event.is_set():
            cycle_number += 1
            try:
                summary = await self.run_cycle(cycle_number)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # one bad cycle must not kill the run
                self.renderer.message(f"[ERROR] cycle {cycle_number} failed: {exc}")
                summary = {"cycle": cycle_number, "error": str(exc), "yield_rate": 0.0}

            summaries.append(summary)
            self._cycles_run = cycle_number
            self.renderer.message(
                f"[cycle {cycle_number}] candidates={summary.get('candidates', 0)} "
                f"validated={summary.get('validated', 0)} "
                f"passed={summary.get('passed', 0)} "
                f"yield={summary.get('yield_rate', 0.0) * 100:.1f}% "
                f"|W|={summary.get('working_size', 0)}"
            )

            if cycle_number % self.config.export_every_cycles == 0:
                self.export({"cycle": cycle_number, **summary})

            # Yield-based abort: a source set that stops producing is a signal to
            # stop burning bandwidth, not to keep looping.
            threshold = self.config.yield_abort_threshold
            if threshold > 0:
                if summary.get("yield_rate", 0.0) < threshold:
                    self._low_yield_streak += 1
                else:
                    self._low_yield_streak = 0
                if self._low_yield_streak >= self.config.yield_abort_cycles:
                    aborted_reason = (
                        f"yield below {threshold * 100:.1f}% for "
                        f"{self._low_yield_streak} consecutive cycles"
                    )
                    self.renderer.message(f"[abort] {aborted_reason}")
                    break

            if self.config.max_cycles and cycle_number >= self.config.max_cycles:
                break

            await self.wait_remaining()

        # Final export so a signalled stop never discards the cycle's work.
        if cycle_number % self.config.export_every_cycles != 0 or self.stop_event.is_set():
            self.export({"final": True, "cycles": cycle_number})

        self.renderer.finish()
        return {
            "cycles": cycle_number,
            "aborted_reason": aborted_reason,
            "stopped_by_signal": self.stop_event.is_set(),
            "working_size": self.store.working_size(),
            "summaries": summaries,
            "store": self.store.stats(),
        }
