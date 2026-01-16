import os
import json
import hashlib
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
    """Compute SHA1 hash of text."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest()

def append_jsonl(path: str, data: dict):
    """Append a JSON object as a line to a file."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")

def read_json(path: str, default=None) -> dict:
    """Read JSON from file."""
    if not os.path.exists(path):
        return default if default is not None else {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def write_json(path: str, data: dict):
    """Write JSON to file."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)