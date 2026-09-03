"""Source registry, configuration loading, and the language-dispatch heuristic.

A "source" is a public endpoint that publishes free proxy candidates. The
registry records how to fetch it (static HTTP vs. a rendered browser) and how
to parse it (raw text, JSON, or an HTML table).
"""

import json
import os
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional
from urllib.parse import urlparse

# Parse kinds
KIND_TEXT = "text"
KIND_JSON = "json"
KIND_HTML = "html"
KIND_AUTO = "auto"

# Renderer / language dispatch
RENDER_PYTHON = "python"
RENDER_JS = "js"
RENDER_AUTO = "auto"

VALID_KINDS = {KIND_TEXT, KIND_JSON, KIND_HTML, KIND_AUTO}
VALID_RENDERERS = {RENDER_PYTHON, RENDER_JS, RENDER_AUTO}


class SourceConfigError(ValueError):
    """Raised for a malformed source definition or config file."""


@dataclass
class Source:
    """One public proxy-list endpoint."""

    id: str
    url: str
    kind: str = KIND_AUTO
    renderer: str = RENDER_AUTO
    protocol: str = "http"
    enabled: bool = True
    respect_robots: bool = True
    notes: str = ""

    def __post_init__(self):
        if not self.id:
            raise SourceConfigError("source id is required")
        parsed = urlparse(self.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise SourceConfigError(f"{self.id}: url must be absolute http(s): {self.url!r}")
        if parsed.username or parsed.password:
            raise SourceConfigError(
                f"{self.id}: credentials in source URLs are not supported "
                "(this tool operates without authentication)"
            )
        if self.kind not in VALID_KINDS:
            raise SourceConfigError(f"{self.id}: kind must be one of {sorted(VALID_KINDS)}")
        if self.renderer not in VALID_RENDERERS:
            raise SourceConfigError(
                f"{self.id}: renderer must be one of {sorted(VALID_RENDERERS)}"
            )

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    def to_row(self) -> Dict:
        return asdict(self)


# Public raw-text/JSON proxy list endpoints. These repositories publish their
# lists specifically for programmatic consumption, which is why raw endpoints
# are preferred here: they avoid HTML scraping, avoid JS rendering, and keep the
# request volume to one GET per source per cycle.
DEFAULT_SOURCES: List[Dict] = [
    {
        "id": "speedx-http",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "kind": "text",
        "renderer": "python",
        "protocol": "http",
        "notes": "Raw ip:port list, HTTP proxies.",
    },
    {
        "id": "speedx-socks5",
        "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "kind": "text",
        "renderer": "python",
        "protocol": "socks5",
        "notes": "Raw ip:port list, SOCKS5 proxies.",
    },
    {
        "id": "monosans-json",
        "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies.json",
        "kind": "json",
        "renderer": "python",
        "protocol": "http",
        "notes": "Structured JSON with protocol and geo fields.",
    },
    {
        "id": "proxifly-http",
        "url": "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt",
        "kind": "text",
        "renderer": "python",
        "protocol": "http",
        "notes": "Raw list, protocol-scheme prefixed.",
    },
    {
        "id": "jetkai-http",
        "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "kind": "text",
        "renderer": "python",
        "protocol": "http",
        "notes": "Raw ip:port list refreshed on a schedule.",
    },
]


def default_sources() -> List[Source]:
    return [Source(**row) for row in DEFAULT_SOURCES]


# --- language dispatch -------------------------------------------------

_ENDPOINT_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\s*[:|]\s*\d{2,5}\b")
_SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
_TABLE_ROW_RE = re.compile(r"<t[rd]\b", re.IGNORECASE)
_SPA_MARKER_RE = re.compile(
    r"(id=[\"']root[\"']|id=[\"']app[\"']|data-reactroot|ng-app|__NEXT_DATA__|"
    r"window\.__NUXT__)",
    re.IGNORECASE,
)


def select_language(source: Source, probe_body: Optional[str] = None) -> str:
    """Heuristic L(s): choose the Python static path or the JS rendered path.

    Declared renderers win outright. For ``auto`` sources the decision comes from
    the probe body: enough parseable ``ip:port`` pairs in the static response
    means Python can do the job and a browser would be wasted overhead.
    """
    if source.renderer in {RENDER_PYTHON, RENDER_JS}:
        return source.renderer
    if source.kind in {KIND_TEXT, KIND_JSON}:
        return RENDER_PYTHON
    if not probe_body:
        # No evidence yet: try the cheap path first and let the caller escalate.
        return RENDER_PYTHON

    endpoints = len(_ENDPOINT_RE.findall(probe_body))
    if endpoints >= 5:
        # The static body already carries the data; rendering adds nothing.
        return RENDER_PYTHON

    scripts = len(_SCRIPT_RE.findall(probe_body))
    rows = len(_TABLE_ROW_RE.findall(probe_body))
    if _SPA_MARKER_RE.search(probe_body) and rows < 10:
        return RENDER_JS
    if scripts >= 5 and endpoints == 0:
        return RENDER_JS
    return RENDER_PYTHON


def detect_kind(content_type: str, body: str) -> str:
    """Resolve a KIND_AUTO source against what the server actually returned."""
    ctype = (content_type or "").partition(";")[0].strip().lower()
    if "json" in ctype:
        return KIND_JSON
    if "html" in ctype or "xml" in ctype:
        return KIND_HTML
    stripped = (body or "").lstrip()
    if stripped[:1] in {"{", "["}:
        return KIND_JSON
    if stripped[:1] == "<":
        return KIND_HTML
    return KIND_TEXT


# --- config loading ----------------------------------------------------


def _load_structured(path: str) -> Dict:
    """Read a JSON config, or a YAML config when PyYAML is available.

    JSON is the dependency-free baseline so the harvester runs against the
    project's pinned requirements. YAML is supported opportunistically.
    """
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()

    suffix = os.path.splitext(path)[1].lower()
    if suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise SourceConfigError(
                f"{path}: YAML config requires PyYAML "
                "(pip install -r requirements-proxyharvest.txt), "
                "or convert the file to JSON"
            ) from exc
        data = yaml.safe_load(raw)
    else:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SourceConfigError(f"{path}: invalid JSON: {exc}") from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise SourceConfigError(f"{path}: top level must be a mapping")
    return data


def load_config(path: Optional[str]) -> Dict:
    """Load a harvester config file, returning {} when no path is given."""
    if not path:
        return {}
    resolved = os.path.abspath(os.path.expanduser(path))
    if not os.path.isfile(resolved):
        raise SourceConfigError(f"config file not found: {resolved}")
    return _load_structured(resolved)


def sources_from_config(config: Dict) -> List[Source]:
    """Build the source list from config, falling back to the built-in set."""
    rows = config.get("sources")
    if not rows:
        return default_sources()
    if not isinstance(rows, list):
        raise SourceConfigError("'sources' must be a list of source mappings")

    sources: List[Source] = []
    seen = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise SourceConfigError(f"sources[{index}] must be a mapping")
        unknown = set(row) - {
            "id", "url", "kind", "renderer", "protocol", "enabled",
            "respect_robots", "notes",
        }
        if unknown:
            raise SourceConfigError(
                f"sources[{index}]: unknown keys {sorted(unknown)}"
            )
        source = Source(**row)
        if source.id in seen:
            raise SourceConfigError(f"duplicate source id: {source.id}")
        seen.add(source.id)
        sources.append(source)
    return sources


def enabled_sources(sources: List[Source]) -> List[Source]:
    return [s for s in sources if s.enabled]
