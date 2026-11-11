"""Live CLI status rendering.

Two modes: a redrawn single line when stdout is a TTY, and plain append-only
lines otherwise, so piping to a log file stays readable. ``--json-status`` swaps
both for one JSON object per state change, for supervision by another process.
"""

import json
import shutil
import sys
import time
from dataclasses import dataclass, asdict, field
from typing import Dict, Optional

PHASE_IDLE = "idle"
PHASE_HARVEST = "harvest"
PHASE_PARSE = "parse"
PHASE_VALIDATE = "validate"
PHASE_CLASSIFY = "classify"
PHASE_EXPORT = "export"
PHASE_WAIT = "wait"
PHASE_STOPPING = "stopping"


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    return f"{minutes:02d}m{secs:02d}s"


@dataclass
class HarvesterState:
    """Everything the status line reports."""

    phase: str = PHASE_IDLE
    cycle: int = 0
    detail: str = ""
    working_size: int = 0
    candidates: int = 0
    validated: int = 0
    passed: int = 0
    yield_rate: float = 0.0
    interval_s: float = 0.0
    cycle_started_at: float = field(default_factory=time.time)
    next_export_at: Optional[float] = None
    last_export: str = "-"
    progress: str = ""

    @property
    def remaining_s(self) -> float:
        if not self.interval_s:
            return 0.0
        return max(0.0, self.interval_s - (time.time() - self.cycle_started_at))

    def to_dict(self) -> Dict:
        data = asdict(self)
        data["remaining_s"] = round(self.remaining_s, 1)
        data["next_export_in_s"] = (
            round(max(0.0, self.next_export_at - time.time()), 1)
            if self.next_export_at
            else None
        )
        return data


class StatusRenderer:
    """Writes state to the terminal without owning the event loop."""

    def __init__(self, json_mode: bool = False, quiet: bool = False, stream=None):
        self.json_mode = json_mode
        self.quiet = quiet
        self.stream = stream or sys.stdout
        self.is_tty = bool(getattr(self.stream, "isatty", lambda: False)())
        self._last_len = 0

    def render(self, state: HarvesterState) -> None:
        if self.quiet:
            return
        if self.json_mode:
            self.stream.write(json.dumps(state.to_dict(), ensure_ascii=False) + "\n")
            self.stream.flush()
            return

        line = self._line(state)
        if self.is_tty:
            width = shutil.get_terminal_size((120, 24)).columns
            line = line[: max(20, width - 1)]
            padding = " " * max(0, self._last_len - len(line))
            self.stream.write("\r" + line + padding)
            self._last_len = len(line)
        else:
            self.stream.write(line + "\n")
        self.stream.flush()

    def _line(self, state: HarvesterState) -> str:
        parts = [
            f"cycle {state.cycle}",
            f"phase={state.phase}",
            f"|W|={state.working_size}",
        ]
        if state.candidates:
            parts.append(f"cand={state.candidates}")
        if state.validated:
            parts.append(f"pass={state.passed}/{state.validated} ({state.yield_rate * 100:.1f}%)")
        if state.interval_s:
            parts.append(f"T-t={format_duration(state.remaining_s)}")
        if state.next_export_at:
            parts.append(f"export in {format_duration(state.next_export_at - time.time())}")
        else:
            parts.append(f"export={state.last_export}")
        if state.progress:
            parts.append(state.progress)
        if state.detail:
            parts.append(state.detail)
        return "  ".join(parts)

    def message(self, text: str) -> None:
        """Emit a durable log line above the status line."""
        if self.quiet:
            return
        if self.json_mode:
            self.stream.write(json.dumps({"message": text}) + "\n")
            self.stream.flush()
            return
        if self.is_tty and self._last_len:
            self.stream.write("\r" + " " * self._last_len + "\r")
            self._last_len = 0
        self.stream.write(text + "\n")
        self.stream.flush()

    def finish(self) -> None:
        if self.is_tty and self._last_len and not self.json_mode:
            self.stream.write("\n")
            self.stream.flush()
            self._last_len = 0
