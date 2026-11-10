import os
import json
import hashlib
import tempfile
from datetime import datetime, timezone

def safe_mkdir(path: str):
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)

def now_run_id() -> str:
    """Generate a run ID based on current timestamp."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def load_lines(path: str) -> list[str]:
    """Load lines from a file, stripping whitespace."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def sha1(text: str) -> str:
    """Compute a stable legacy artifact ID; never used for security."""
    return hashlib.sha1(text.encode("utf-8"), usedforsecurity=False).hexdigest()

def append_jsonl(path: str, data: dict):
    """Append a JSON object as a line to a file."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

def append_jsonl_rows(path: str, rows: list):
    """Append many JSON objects with a single open/close."""
    if not rows:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows))

def read_jsonl(path: str) -> list:
    """Read JSON lines, skipping blank or damaged rows (e.g. a torn final write)."""
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except (ValueError, TypeError):
                continue
    return rows

def utc_iso(ts: float = None) -> str:
    """ISO-8601 UTC timestamp for provenance records."""
    moment = datetime.fromtimestamp(ts, timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")

def read_json(path: str, default=None) -> dict:
    """Read JSON from file."""
    if not os.path.exists(path):
        return default if default is not None else {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError, TypeError):
        return default if default is not None else {}

def write_json(path: str, data: dict):
    """Write JSON atomically so an interrupted checkpoint cannot corrupt prior state."""
    parent = os.path.dirname(os.path.abspath(path))
    safe_mkdir(parent)
    temp_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=f".{os.path.basename(path)}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = handle.name
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        sync_directory(parent)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)


def sync_directory(path):
    """Persist rename metadata on POSIX; Windows provides no directory fsync here."""
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sync_file(path):
    """Flush a completed file through a descriptor Windows permits fsync to use."""
    with open(path, "rb+") as handle:
        handle.flush()
        os.fsync(handle.fileno())
