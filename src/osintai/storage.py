import os
import json
import hashlib
import tempfile
from datetime import datetime

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
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
