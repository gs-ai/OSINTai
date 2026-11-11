"""Working-set exports: CSV, JSON, JSONL, and a plain endpoint list.

Every export carries a manifest recording how the set was produced and what the
``network_class`` column does and does not mean. An export handed to someone
else without that context invites exactly the misreading this tool is built to
avoid.
"""

import csv
import io
import json
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from ..storage import safe_mkdir, write_json

CSV_COLUMNS = [
    "key", "ip", "port", "protocol", "source_id", "latency_ms", "anonymity",
    "exit_ip", "network_class", "classification_confidence",
    "classification_basis", "asn", "as_org", "country", "ptr",
    "first_seen", "last_ok", "ok_count", "fail_count",
]

CLASSIFICATION_NOTICE = (
    "network_class values ending in '_indicated' are heuristic reads of ASN and "
    "PTR evidence, not verified subscriber-line records. Treat them as leads "
    "requiring confirmation. classification_basis records which signals fired. "
    "Public free proxies are unvetted third-party infrastructure: assume traffic "
    "through them may be observed or altered, and never route authenticated, "
    "privileged, or case-sensitive traffic over them."
)


def _atomic_write_text(path: str, text: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    safe_mkdir(parent)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=parent, newline="",
            prefix=f".{os.path.basename(path)}.", suffix=".tmp", delete=False,
        ) as handle:
            temp_path = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


@dataclass
class ExportResult:
    stamp: str
    directory: str
    files: List[str]
    count: int


def stamp_now() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def write_csv(path: str, rows: List[Dict]) -> None:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({column: row.get(column, "") for column in CSV_COLUMNS})
    _atomic_write_text(path, handle.getvalue())


def write_jsonl(path: str, rows: List[Dict]) -> None:
    lines = [json.dumps(row, ensure_ascii=False) for row in rows]
    _atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))


def write_endpoints(path: str, rows: List[Dict]) -> None:
    """Plain ``scheme://ip:port`` list, consumable by ``--proxies``."""
    lines = []
    for row in rows:
        scheme = "http" if row.get("protocol") in {"http", "https"} else row.get("protocol")
        lines.append(f"{scheme}://{row['ip']}:{row['port']}")
    _atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))


def build_manifest(rows: List[Dict], context: Optional[Dict] = None) -> Dict:
    classes: Dict[str, int] = {}
    grades: Dict[str, int] = {}
    for row in rows:
        klass = row.get("network_class") or "unknown"
        classes[klass] = classes.get(klass, 0) + 1
        grade = row.get("anonymity") or "unknown"
        grades[grade] = grades.get(grade, 0) + 1

    latencies = [r["latency_ms"] for r in rows if isinstance(r.get("latency_ms"), (int, float))]
    manifest = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "working_set_size": len(rows),
        "by_network_class": classes,
        "by_anonymity": grades,
        "latency_ms": {
            "min": round(min(latencies), 1) if latencies else None,
            "max": round(max(latencies), 1) if latencies else None,
            "mean": round(sum(latencies) / len(latencies), 1) if latencies else None,
        },
        "classification_notice": CLASSIFICATION_NOTICE,
    }
    if context:
        manifest["run"] = context
    return manifest


def export_working_set(
    directory: str,
    rows: List[Dict],
    formats: Optional[List[str]] = None,
    context: Optional[Dict] = None,
    stamp: Optional[str] = None,
) -> ExportResult:
    """Write the working set in the requested formats plus a manifest.

    ``latest.*`` copies are refreshed alongside the stamped files so a downstream
    consumer can point at a stable path.
    """
    formats = formats or ["csv", "json", "txt"]
    directory = os.path.abspath(os.path.expanduser(directory))
    safe_mkdir(directory)
    stamp = stamp or stamp_now()
    written: List[str] = []

    export_rows = [{k: v for k, v in row.items() if k != "last_ok_epoch"} for row in rows]

    if "csv" in formats:
        for name in (f"working_set_{stamp}.csv", "working_set_latest.csv"):
            path = os.path.join(directory, name)
            write_csv(path, export_rows)
            written.append(path)

    if "json" in formats:
        payload = {"manifest": build_manifest(export_rows, context), "proxies": export_rows}
        for name in (f"working_set_{stamp}.json", "working_set_latest.json"):
            path = os.path.join(directory, name)
            write_json(path, payload)
            written.append(path)

    if "jsonl" in formats:
        for name in (f"working_set_{stamp}.jsonl", "working_set_latest.jsonl"):
            path = os.path.join(directory, name)
            write_jsonl(path, export_rows)
            written.append(path)

    if "txt" in formats:
        for name in (f"working_set_{stamp}.txt", "working_set_latest.txt"):
            path = os.path.join(directory, name)
            write_endpoints(path, export_rows)
            written.append(path)

    manifest_path = os.path.join(directory, f"manifest_{stamp}.json")
    write_json(manifest_path, build_manifest(export_rows, context))
    written.append(manifest_path)

    return ExportResult(stamp=stamp, directory=directory, files=written, count=len(export_rows))
