"""Temporal analysis over crawled material.

The event stream combines crawl timestamps with dates found in page content, and every
event keeps its source URL.

Original timestamps are preserved on every event. Normalization produces an additional
field; it never overwrites what the source said.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from .provenance import (
    DERIVED,
    HIGH,
    LOW,
    MEDIUM,
    OBSERVED,
    CheckResult,
    Finding,
    deterministic_confidence,
    source_support,
)

# Event kinds
FETCH = "page_fetched"
CONTENT_DATE = "date_in_content"


@dataclass
class Event:
    """One dated thing, with the raw form it was written in and where it came from."""

    when: datetime
    kind: str
    source: str
    detail: str = ""
    raw: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.when.isoformat(),
            "date": self.when.date().isoformat(),
            "kind": self.kind,
            "source": self.source,
            "detail": self.detail,
            "raw": self.raw,
        }


# Written date forms worth accepting. Model-reported `key_dates` are usually prose dates
# ("Feb 28, 2026"), and dropping them would leave the timeline built almost entirely from
# fetch timestamps, which say when OSINTai looked rather than when anything happened.
_DATE_FORMATS = (
    "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d",
    "%b %d, %Y", "%B %d, %Y",
    "%b %d %Y", "%B %d %Y",
    "%d %b %Y", "%d %B %Y",
    "%d-%b-%Y", "%d-%B-%Y",
    "%B %Y", "%b %Y",
    "%Y-%m", "%Y",
)


def parse_timestamp(value: str) -> Optional[datetime]:
    """Parse ISO-8601 and the common written date forms. Trailing Z is accepted."""
    text = (value or "").strip().rstrip(".,;")
    if not text:
        return None
    iso_text = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso_text)
    except ValueError:
        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _plausible(when: datetime) -> bool:
    """Reject dates a web crawl cannot meaningfully be reporting on."""
    now = datetime.now(timezone.utc)
    return datetime(1990, 1, 1, tzinfo=timezone.utc) <= when <= now + timedelta(days=366 * 2)


def build_events(
    page_records: Iterable[Dict[str, Any]],
    content_dates: Optional[Dict[str, List[str]]] = None,
) -> Tuple[List[Event], List[str]]:
    """Assemble the run's event stream. Returns events and non-fatal parse errors."""
    events: List[Event] = []
    errors: List[str] = []

    for record in page_records or []:
        url = record.get("url")
        fetched_at = record.get("fetched_at")
        if not url or not fetched_at:
            continue
        try:
            when = datetime.fromtimestamp(float(fetched_at), tz=timezone.utc)
        except (TypeError, ValueError, OSError) as exc:
            errors.append(f"{url}: unreadable fetch timestamp {fetched_at!r}: {exc}")
            continue
        events.append(Event(
            when=when,
            kind=FETCH,
            source=url,
            detail=(record.get("title") or "")[:120],
            raw=str(fetched_at),
        ))

    for url, raw_dates in (content_dates or {}).items():
        for raw in raw_dates:
            when = parse_timestamp(raw)
            if when is None:
                errors.append(f"{url}: could not parse date {raw!r}")
                continue
            if not _plausible(when):
                continue
            events.append(Event(
                when=when, kind=CONTENT_DATE, source=url,
                detail="date published in page content", raw=raw,
            ))

    events.sort(key=lambda e: e.when)
    return events, errors


def analyze_timeline(events: List[Event], gap_threshold_days: int = 90) -> CheckResult:
    """Order events, measure gaps, and flag silence, bursts and the open trailing window."""
    result = CheckResult(check_name="Temporal Analysis")

    content_events = [e for e in events if e.kind == CONTENT_DATE]
    if not events:
        result.notes.append("No dated events available. Temporal analysis skipped.")
        return result

    for index, event in enumerate(events):
        gap = "" if index == 0 else (event.when - events[index - 1].when).days
        row = event.to_dict()
        row["gap_from_previous_days"] = gap
        result.rows.append(row)

    if len(content_events) < 2:
        result.notes.append(
            f"{len(content_events)} content date(s) recovered; gap analysis needs at least 2."
        )
    else:
        for before, after in zip(content_events, content_events[1:]):
            gap_days = (after.when - before.when).days
            if gap_days <= gap_threshold_days:
                continue
            result.findings.append(Finding(
                check="Activity Gap",
                item=f"{before.when.date().isoformat()} to {after.when.date().isoformat()}",
                reason=(
                    f"Chronological gap of {gap_days} day(s) between dated content, exceeding the "
                    f"{gap_threshold_days}-day threshold."
                ),
                next_step=(
                    "Determine whether this is genuine silence, content removed since publication, "
                    "activity that moved to another channel, or simply a limit of what this crawl "
                    "reached."
                ),
                origin=DERIVED,
                priority=MEDIUM,
                sources=[before.source, after.source],
                evidence={
                    "gap_start": before.when.date().isoformat(),
                    "gap_end": after.when.date().isoformat(),
                    "gap_days": gap_days,
                    "last_before": before.raw,
                    "first_after": after.raw,
                },
                method="chronological_gap",
                confidence=[deterministic_confidence(
                    0.6, "gap in crawled content only; absence of records is not absence of activity")],
            ))

        latest = content_events[-1]
        trailing = (datetime.now(timezone.utc) - latest.when).days
        if trailing > gap_threshold_days:
            result.findings.append(Finding(
                check="Open Trailing Gap",
                item=f"{latest.when.date().isoformat()} to present",
                reason=(
                    f"Most recent dated content is {trailing} day(s) old, exceeding the "
                    f"{gap_threshold_days}-day threshold."
                ),
                next_step=(
                    "Re-run collection against current sources to establish whether activity "
                    "continued outside what this run captured."
                ),
                origin=DERIVED,
                priority=HIGH,
                sources=[latest.source],
                evidence={
                    "last_dated_content": latest.when.date().isoformat(),
                    "days_since": trailing,
                },
                method="trailing_gap",
                confidence=[deterministic_confidence(0.6, "based on crawled content dates only")],
            ))

        # Bursts: days carrying far more dated content than the active-day average.
        per_day: Dict[str, List[Event]] = {}
        for event in content_events:
            per_day.setdefault(event.when.date().isoformat(), []).append(event)
        if len(per_day) >= 3:
            counts = [len(v) for v in per_day.values()]
            mean = sum(counts) / len(counts)
            for day, day_events in sorted(per_day.items()):
                if len(day_events) >= max(3, mean * 3):
                    sources = sorted({e.source for e in day_events})
                    result.findings.append(Finding(
                        check="Activity Burst",
                        item=day,
                        reason=(
                            f"{len(day_events)} dated items on one day against an active-day mean "
                            f"of {mean:.1f}."
                        ),
                        next_step="Establish what happened on this date and whether the items share a cause.",
                        origin=DERIVED,
                        priority=MEDIUM,
                        sources=sources[:25],
                        evidence={"day": day, "item_count": len(day_events), "mean": round(mean, 2)},
                        method="daily_burst",
                        confidence=[deterministic_confidence(0.55, "frequency observation over this run"),
                                    source_support(sources)],
                    ))

    first, last = events[0], events[-1]
    result.stats = {
        "event_count": len(events),
        "content_date_count": len(content_events),
        "window_start": first.when.isoformat(),
        "window_end": last.when.isoformat(),
        "window_days": (last.when - first.when).days,
    }
    result.notes.append(
        f"Ordered {len(events)} event(s) spanning {result.stats['window_days']} day(s). "
        f"Flagged {result.finding_count} temporal finding(s)."
    )
    return result
