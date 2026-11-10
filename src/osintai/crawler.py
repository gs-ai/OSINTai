import os
import json
import time
import asyncio
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, urlsplit

import httpx

from .normalize import canonical_url
from .storage import (sha1, safe_mkdir, append_jsonl, append_jsonl_rows, read_json,
                      read_jsonl, write_json, utc_iso)
from .extractor import Extractor
from .fetcher import AsyncFetcher, FetchRejected
from .ollama_api import OllamaAPI
from .model_quality import page_status
from .isolation import async_isolated_call
from .dedupe import sha1_text, simhash_64, hamming64
from .analyzer import compute_page_signal
from .hunt import hunt_leads
from .graph_export import export_graph
from .prompts import STANDARD, page_prompt

def is_probably_html(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("content-type", "") or ""
    return ("text/html" in ctype) or ("application/xhtml+xml" in ctype) or (ctype.strip() == "")

def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""

@dataclass
class PageRecord:
    url: str
    status_code: int
    fetched_at: float
    content_sha1: str
    title: str
    text_len: int
    out_links_count: int
    saved_raw_path: str
    saved_text_path: str
    simhash64: int
    # Provenance: how this page was reached and when.
    fetched_at_utc: str = ""
    depth: int = 0
    round: int = 0
    parent_url: str = ""
    discovered_via: str = ""
    discovery_path: Optional[List[str]] = None

STATE_VERSION = 2
UNLIMITED_DEPTH = 1_000_000
HOST_FAILURE_LIMIT = 5      # consecutive transport failures before a host is abandoned
MAX_HOST_BACKOFF_S = 60.0
# Never HTML: requesting these only spends traffic the fetcher would reject anyway.
NON_HTML_SUFFIXES = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tif", ".tiff",
    ".css", ".js", ".mjs", ".json", ".xml", ".rss", ".atom", ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".iso", ".dmg", ".exe", ".msi",
    ".apk", ".bin", ".mp3", ".mp4", ".m4a", ".m4v", ".avi", ".mov", ".mkv", ".webm", ".wav", ".ogg",
)

def _clock(seconds: float) -> str:
    seconds = max(0, int(seconds))
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"

def _new_stats() -> Dict:
    return {
        "sessions": 0, "elapsed_s": 0.0, "rounds_completed": 0,
        "urls_discovered": 0, "urls_processed": 0, "records_collected": 0,
        "duplicates": 0, "skipped": 0, "failed": 0,
        "policy_skipped": 0, "frontier_dropped": 0,
        "stop_reason": "", "rounds": [],
    }

def _extract_page(extractor, url, html, hunt_terms, hunt_limit):
    title, text = extractor.html_to_text(html)
    return (title, text, extractor.extract_links(url, html),
            extractor.extract_indicators(url, text, html),
            hunt_leads(text, hunt_terms, max_leads=hunt_limit), simhash_64(text))


class AsyncCrawler:
    """Breadth-first, round-based collector.

    Round N fetches every URL discovered in round N-1 (round 1 is the seeds), so each
    round widens the source set. Collection stops when the frontier is empty, the URL
    budget is spent, or the optional runtime expires; in every case the unfinished
    frontier is checkpointed so the same run directory can be resumed.
    """

    def __init__(
        self,
        seed_urls: List[str],
        max_depth: int,
        max_urls: int,
        run_dir: str,
        fetcher: AsyncFetcher,
        extractor: Extractor,
        same_domain_only: bool,
        resume: bool,
        concurrency: int,
        per_host_concurrency: int,
        use_ollama: bool,
        model_analyze: str,
        model_embed: str,
        hunt_terms: List[str],
        hunt_max_leads: int,
        prompt_profile: str = STANDARD,
        extraction_timeout_s: float = 30.0,
        runtime_s: Optional[float] = None,
        max_frontier: int = 50_000,
        max_per_host: int = 0,
        progress_interval_s: float = 5.0,
        checkpoint_interval_s: float = 15.0,
        shutdown_grace_s: float = 20.0,
    ):
        self.extraction_timeout_s = extraction_timeout_s
        self.extraction_sema = asyncio.Semaphore(2)
        self.prompt_profile = prompt_profile
        self.seed_urls = seed_urls
        self.allowed_seed_hosts = {host_of(url) for url in seed_urls if host_of(url)}
        self.max_depth = max_depth
        self.max_urls = max_urls
        self.run_dir = run_dir
        self.fetcher = fetcher
        self.extractor = extractor
        self.same_domain_only = same_domain_only
        self.resume = resume

        self.concurrency = max(1, concurrency)
        self.per_host_concurrency = max(1, per_host_concurrency)

        self.runtime_s = runtime_s if runtime_s and runtime_s > 0 else None
        self.max_frontier = max(1, max_frontier)
        self.max_per_host = max(0, max_per_host)
        self.progress_interval_s = progress_interval_s
        self.checkpoint_interval_s = checkpoint_interval_s
        self.shutdown_grace_s = max(0.0, shutdown_grace_s)
        self.deadline: Optional[float] = None
        self._session_start = time.monotonic()
        self._prior_elapsed = 0.0

        self.use_ollama = use_ollama
        self.model_analyze = model_analyze
        self.model_embed = model_embed

        self.hunt_terms = hunt_terms
        self._hunt_lower = [term.lower() for term in hunt_terms or [] if term]
        self.hunt_max_leads = hunt_max_leads

        self.raw_dir = os.path.join(run_dir, "pages_raw")
        self.text_dir = os.path.join(run_dir, "pages_text")
        self.analysis_dir = os.path.join(run_dir, "analysis")
        self.embed_dir = os.path.join(run_dir, "embeddings")
        safe_mkdir(self.raw_dir)
        safe_mkdir(self.text_dir)
        safe_mkdir(self.analysis_dir)
        safe_mkdir(self.embed_dir)

        self.urls_jsonl = os.path.join(run_dir, "urls_crawled.jsonl")
        self.indicators_jsonl = os.path.join(run_dir, "indicators.jsonl")
        self.page_scores_jsonl = os.path.join(run_dir, "page_scores.jsonl")
        self.hunt_jsonl = os.path.join(run_dir, "hunt.jsonl")
        self.edges_jsonl = os.path.join(run_dir, "discovery_edges.jsonl")
        self.failures_jsonl = os.path.join(run_dir, "fetch_failures.jsonl")
        self.state_path = os.path.join(run_dir, "crawl_state.json")
        self.stats_path = os.path.join(run_dir, "crawl_stats.json")
        self.proxy_state = os.path.join(run_dir, "proxy_pool.json")

        self.visited: Set[str] = set()
        # `queue` is the round being fetched; `pending` is the next round's frontier,
        # url -> (depth, priority). `queued` is the union, for O(1) duplicate checks.
        self.queue: Deque[Tuple[str, int]] = deque()
        self.pending: Dict[str, Tuple[int, float]] = {}
        self.queued: Set[str] = set()
        self.in_progress: Set[str] = set()
        # url -> (parent url or "", discovery method); the discovery tree.
        self.parent: Dict[str, Tuple[str, str]] = {}
        self._edge_buffer: List[Dict] = []
        self.stats = _new_stats()
        self._round_open = False
        self._round_base: Dict[str, int] = {}
        self._round_depth = 0

        # near-duplicate tracking by simhash
        self.simhash_seen: List[int] = []

        # per-host politeness: concurrency, request counts, backoff, failure streaks
        self.host_sema: Dict[str, asyncio.Semaphore] = {}
        self.host_pages: Counter = Counter()
        self.host_backoff: Dict[str, float] = {}
        self.host_failures: Counter = Counter()
        self.ollama_sema = asyncio.Semaphore(max(1, min(2, self.concurrency)))

        self.ollama = OllamaAPI() if self.use_ollama else None

        loaded = self.resume and self._load_state()
        if not loaded or not (self.queue or self.pending):
            self._seed()
        self._flush_edges()

    # ------------------------------------------------------------------ state

    def _seed(self):
        for url in self.seed_urls:
            url = canonical_url(url)
            if self._accept(url, 0, "", "seed"):
                self.queue.append((url, 0))
        if self.queue:
            self._open_round(0)

    def _load_state(self) -> bool:
        st = read_json(self.state_path, default=None)
        if not st:
            return False

        self.visited = set(st.get("visited", []))
        self.queue.clear()
        self.pending.clear()
        self.queued.clear()
        self.in_progress.clear()
        self.simhash_seen = st.get("simhash_seen", [])[:5000]
        self.host_pages = Counter(st.get("host_pages", {}))
        stats = st.get("stats")
        if isinstance(stats, dict):
            self.stats = {**_new_stats(), **stats}
        self._prior_elapsed = float(self.stats.get("elapsed_s", 0.0) or 0.0)

        # Rebuild the discovery tree; the last edge for a URL is the one in force.
        for row in read_jsonl(self.edges_jsonl):
            child = row.get("child")
            if child:
                self.parent[child] = (row.get("parent") or "", row.get("via") or "link")

        def usable(url, depth):
            return (isinstance(url, str) and url not in self.visited and url not in self.queued
                    and depth <= self.max_depth and self._scoped(url))

        # Items were canonicalized when first accepted; restore them without re-recording.
        for item in st.get("queue", []):
            if isinstance(item, (list, tuple)) and len(item) == 2 and usable(item[0], int(item[1])):
                self.queue.append((item[0], int(item[1])))
                self.queued.add(item[0])
        for item in st.get("pending", []):
            if isinstance(item, (list, tuple)) and len(item) == 3 and usable(item[0], int(item[1])):
                self.pending[item[0]] = (int(item[1]), float(item[2]))
                self.queued.add(item[0])
        if self.queue:
            # An interrupted round continues; it is not counted as a new one.
            self._open_round(self.queue[0][1])
        return True

    def _save_state(self):
        self._flush_edges()
        self.stats["elapsed_s"] = round(self.elapsed_s(), 3)
        write_json(self.state_path, {
            "version": STATE_VERSION,
            "saved_at": utc_iso(),
            "seed_urls": self.seed_urls,
            "visited": sorted(self.visited),
            "queue": [list(item) for item in self.queue],
            "pending": [[url, depth, priority] for url, (depth, priority) in self.pending.items()],
            "simhash_seen": self.simhash_seen[-5000:],
            "host_pages": dict(self.host_pages),
            "stats": self.stats,
        })
        write_json(self.stats_path, {
            **self.stats,
            "saved_at": utc_iso(),
            "runtime_limit_s": self.runtime_s,
            "frontier_remaining": len(self.queued),
            "hosts_contacted": len(self.host_pages),
            "resumable": bool(self.queued),
        })

        # proxy pool snapshot if present
        if getattr(self.fetcher, "proxy_pool", None):
            try:
                write_json(self.proxy_state, self.fetcher.proxy_pool.as_dict())
            except (OSError, TypeError, ValueError) as exc:
                print(f"[WARN] could not save proxy state: {exc}")

    def _flush_edges(self):
        if self._edge_buffer:
            append_jsonl_rows(self.edges_jsonl, self._edge_buffer)
            self._edge_buffer = []

    # --------------------------------------------------------------- frontier

    def _priority(self, url: str, parent_score: float, via: str) -> float:
        """Lower sorts first: hunt matches, strong parents, new hosts, shallow paths."""
        parts = urlsplit(url)
        score = min(self.host_pages[(parts.hostname or "").lower()], 50) * 0.1
        score += 0.2 * parts.path.count("/") + (0.5 if parts.query else 0.0) + len(url) / 200.0
        score -= 0.3 * min(max(parent_score, 0.0), 10.0)
        if via == "hunt":
            score -= 3.0
        lowered = url.lower()
        if any(term in lowered for term in self._hunt_lower):
            score -= 2.0
        return round(score, 4)

    def _accept(self, url: str, depth: int, parent: str, via: str) -> bool:
        """Shared admission test; records the discovery edge for an accepted URL."""
        if not url or depth > self.max_depth:
            return False
        if url in self.visited or url in self.queued or url in self.in_progress:
            return False
        if not self._scoped(url):
            return False
        try:
            path = urlsplit(url).path.lower()
        except ValueError:
            return False
        if path.endswith(NON_HTML_SUFFIXES):
            return False
        host = host_of(url)
        if self.max_per_host and self.host_pages[host] >= self.max_per_host:
            return False
        if self.host_failures[host] >= HOST_FAILURE_LIMIT:
            return False
        if len(self.queued) >= self.max_frontier and not self._trim_pending():
            self.stats["frontier_dropped"] += 1
            return False
        self.queued.add(url)
        self.parent[url] = (parent, via)
        self.stats["urls_discovered"] += 1
        self._edge_buffer.append({
            "child": url, "parent": parent, "via": via, "depth": depth,
            "round": self.current_round(), "discovered_at": utc_iso(),
        })
        return True

    def _enqueue(self, url: str, depth: int, parent: str = "", via: str = "link",
                 parent_score: float = 0.0) -> bool:
        """Queue a newly discovered URL for the next round."""
        url = canonical_url(url)
        if not self._accept(url, depth, parent, via):
            return False
        self.pending[url] = (depth, self._priority(url, parent_score, via))
        return True

    def _trim_pending(self) -> bool:
        """Frontier is full: evict the lowest-priority tenth of the next round."""
        if not self.pending:
            return False
        ranked = sorted(self.pending.items(), key=lambda item: item[1][1])
        for url, _ in ranked[-max(1, len(ranked) // 10):]:
            del self.pending[url]
            self.queued.discard(url)
            self.parent.pop(url, None)
            self.stats["frontier_dropped"] += 1
        return True

    def current_round(self) -> int:
        return self.stats["rounds_completed"] + 1

    def _open_round(self, depth: int):
        self._round_open = True
        self._round_depth = depth
        self._round_base = {key: self.stats[key] for key in
                            ("urls_discovered", "urls_processed", "records_collected")}

    def _close_round(self):
        if not self._round_open:
            return
        self._round_open = False
        self.stats["rounds"].append({
            "round": self.current_round(), "depth": self._round_depth, "finished_at": utc_iso(),
            **{key: self.stats[key] - base for key, base in self._round_base.items()},
        })
        self.stats["rounds_completed"] += 1

    def _promote_round(self) -> bool:
        """Close the finished round and make its discoveries the next round's queue."""
        self._close_round()
        if not self.pending:
            return False
        depth = min(item[0] for item in self.pending.values())
        by_host: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        for url, (item_depth, priority) in self.pending.items():
            if item_depth == depth:
                by_host[host_of(url)].append((priority, url))
        # Round-robin across hosts, best-first within each, so no single source
        # monopolizes the round and requests to any one host are spread out.
        ordered = sorted(
            (rank, priority, url)
            for entries in by_host.values()
            for rank, (priority, url) in enumerate(sorted(entries))
        )
        for _, _, url in ordered:
            del self.pending[url]
            self.queue.append((url, depth))
        self._open_round(depth)
        return True

    def discovery_path(self, url: str) -> List[str]:
        """Seed-to-URL chain reconstructed from the discovery tree."""
        path = [url]
        seen = {url}
        while len(path) < 64:
            parent = self.parent.get(path[-1], ("", ""))[0]
            if not parent or parent in seen:
                break
            path.append(parent)
            seen.add(parent)
        return path[::-1]

    # ------------------------------------------------------------- politeness

    def _host_lock(self, url: str) -> asyncio.Semaphore:
        h = host_of(url)
        if h not in self.host_sema:
            self.host_sema[h] = asyncio.Semaphore(self.per_host_concurrency)
        return self.host_sema[h]

    def _host_slow_down(self, host: str, retry_after: str = ""):
        delay = max(2.0, self.host_backoff.get(host, 0.0) * 2)
        if retry_after and retry_after.strip().isdigit():
            delay = max(delay, float(retry_after.strip()))
        self.host_backoff[host] = min(MAX_HOST_BACKOFF_S, delay)

    def _host_ok(self, host: str):
        self.host_failures.pop(host, None)
        delay = self.host_backoff.get(host, 0.0) / 2
        if delay < 0.5:
            self.host_backoff.pop(host, None)
        else:
            self.host_backoff[host] = delay

    def _scoped(self, url: str) -> bool:
        if not url:
            return False
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
        except ValueError:
            return False
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
            return False
        if not host:
            return False
        if self.same_domain_only and host not in self.allowed_seed_hosts:
            return False
        return True

    def _dedupe_near(self, text: str, sh=None) -> Tuple[bool, int]:
        sh = simhash_64(text) if sh is None else sh
        # if very close to any prior simhash, drop it
        for prev in self.simhash_seen[-400:]:
            if hamming64(sh, prev) <= 3:
                return True, sh
        self.simhash_seen.append(sh)
        if len(self.simhash_seen) > 6000:
            del self.simhash_seen[:-5000]
        return False, sh

    def _analysis_prompt(self, url: str, title: str, text: str) -> str:
        # Delegates to the prompt registry. The 'standard' profile is the same text this
        # method has always produced, so osint-tuned-v3 sees identical input.
        return page_prompt(url, title, text, self.prompt_profile)

    # ------------------------------------------------------------- collection

    def elapsed_s(self) -> float:
        return self._prior_elapsed + (time.monotonic() - self._session_start)

    def _expired(self) -> bool:
        return self.deadline is not None and time.monotonic() >= self.deadline

    def _done(self, url: str, outcome: str):
        self.visited.add(url)
        self.stats["urls_processed"] += 1
        self.stats[outcome] += 1

    async def _process_one(self, client: httpx.AsyncClient, url: str, depth: int) -> bool:
        """Collect one URL. Returns False when the URL was deferred and must be requeued."""
        url = canonical_url(url)
        if not url or url in self.visited:
            return True
        if depth > self.max_depth:
            return True
        if not self._scoped(url):
            return True
        if len(self.visited) >= self.max_urls or self._expired():
            return False

        host = host_of(url)
        lock = self._host_lock(url)
        async with lock:
            delay = self.host_backoff.get(host, 0.0)
            if delay:
                await asyncio.sleep(delay)
                if self._expired():
                    return False
            try:
                resp = await self.fetcher.get(client, url, redirect_validator=self._scoped)
            except FetchRejected as e:
                self._done(url, "skipped")
                print(f"[SKIP] {url} -> {e}")
                return True
            except Exception as e:
                self.host_failures[host] += 1
                self._host_slow_down(host)
                self._done(url, "failed")
                append_jsonl(self.failures_jsonl, {
                    "url": url, "depth": depth, "error": str(e)[:300], "failed_at": utc_iso(),
                })
                print(f"[FAIL] {url} -> {e}")
                return True

        requested_url = url
        final_url = canonical_url(str(resp.url))
        if not final_url or not self._scoped(final_url):
            self._done(url, "skipped")
            print(f"[SKIP] redirect outside seed domains: {url} -> {final_url}")
            return True
        if final_url != requested_url:
            self.visited.add(requested_url)
            if final_url in self.visited or final_url in self.in_progress:
                # Another URL already led here; do not collect the page twice.
                self._done(requested_url, "duplicates")
                return True
            if final_url not in self.parent:
                self.parent[final_url] = (requested_url, "redirect")
                self._edge_buffer.append({
                    "child": final_url, "parent": requested_url, "via": "redirect", "depth": depth,
                    "round": self.current_round(), "discovered_at": utc_iso(),
                })
        url = final_url
        status = resp.status_code
        if status in (429, 503):
            self._host_slow_down(host, resp.headers.get("retry-after", ""))
        else:
            self._host_ok(host)
        if status != 200 or not is_probably_html(resp):
            self._done(url, "skipped")
            print(f"[SKIP] {status} {url}")
            return True

        html = resp.text
        rid = sha1(url)
        raw_path = os.path.join(self.raw_dir, f"{rid}.html")
        # Preserve the response even when a parser defects or exceeds its deadline.
        with open(raw_path, "w", encoding="utf-8", errors="ignore") as handle:
            handle.write(html)
        try:
            async with self.extraction_sema:
                title, text, out_links, indicators, hunt, sh = await async_isolated_call(
                    _extract_page, self.extractor, url, html, self.hunt_terms, self.hunt_max_leads,
                    timeout_s=self.extraction_timeout_s)
        except Exception as exc:
            append_jsonl(os.path.join(self.run_dir, "extraction_failures.jsonl"), {
                "url": url, "saved_raw_path": raw_path,
                "status": "timed_out" if isinstance(exc, TimeoutError) else "failed",
                "error": str(exc),
            })
            self._done(url, "failed")
            print(f"[FAIL] extraction {url}: {exc}")
            return True

        # near-dup check
        is_near_dup, sh = self._dedupe_near(text, sh)
        if is_near_dup:
            self._done(url, "duplicates")
            print(f"[DUP]  depth={depth:02d} {url}")
            return True

        text_path = os.path.join(self.text_dir, f"{rid}.txt")
        with open(text_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text)

        try:
            analysis = await self._model_pass(url, rid, title, text)
        except asyncio.CancelledError:
            # Shutdown interrupted this page before anything was recorded. Forget its
            # fingerprint so the resumed fetch is not rejected as its own duplicate.
            if sh in self.simhash_seen:
                self.simhash_seen.remove(sh)
            raise

        # Everything below is synchronous: a page is recorded completely or not at all.
        now = time.time()
        parent_url, via = self.parent.get(url, ("", ""))
        page = PageRecord(
            url=url,
            status_code=status,
            fetched_at=now,
            content_sha1=sha1_text(html),
            title=(title or "")[:200],
            text_len=len(text),
            out_links_count=len(out_links),
            saved_raw_path=raw_path,
            saved_text_path=text_path,
            simhash64=sh,
            fetched_at_utc=utc_iso(now),
            depth=depth,
            round=self.current_round(),
            parent_url=parent_url,
            discovered_via=via,
            discovery_path=self.discovery_path(url),
        )
        append_jsonl(self.urls_jsonl, asdict(page))
        append_jsonl(self.indicators_jsonl, indicators)

        score = compute_page_signal(indicators, analysis if isinstance(analysis, dict) else {})
        scored = {
            "url": url,
            "title": page.title,
            "score": score,
            "summary": analysis.get("summary") if isinstance(analysis, dict) else "",
            "risk_flags": analysis.get("risk_flags") if isinstance(analysis, dict) else []
        }
        append_jsonl(self.page_scores_jsonl, scored)

        # Discoveries feed the next round; links from stronger pages are fetched first.
        for lk in out_links:
            self._enqueue(lk, depth + 1, url, "link", score)
        # hunt mode on every page (lightweight)
        if hunt.get("hits") or hunt.get("lead_urls"):
            append_jsonl(self.hunt_jsonl, {"url": url, "depth": depth, **hunt})
            for u in hunt.get("lead_urls", [])[: self.hunt_max_leads]:
                self._enqueue(u, depth + 1, url, "hunt", score)
        self._flush_edges()

        self._done(url, "records_collected")
        print(f"[OK] depth={depth:02d} links={len(out_links):03d} score={score:05.2f} text={len(text):05d} {url}")
        return True

    async def _model_pass(self, url: str, rid: str, title: str, text: str) -> Dict:
        analysis = {}
        if self.use_ollama and self.ollama and len(text) > 250:
            prompt = self._analysis_prompt(url, title, text)
            try:
                async with self.ollama_sema:
                    response = await self.ollama.async_generate_result(self.model_analyze, prompt, timeout_s=140.0)
                payload = response["payload"]
                model_status = page_status(payload) if response["status"] == "ok" else response["status"]
                analysis = dict(payload) if model_status == "ok" else {}
                analysis.update(url=url, title=title, _model=self.model_analyze, _model_status=model_status)
            except Exception:
                analysis = {"url": url, "title": title, "_model": self.model_analyze, "_model_status": "error"}

            out_json = os.path.join(self.analysis_dir, f"{rid}.analysis.json")
            write_json(out_json, analysis)

        else:
            write_json(os.path.join(self.analysis_dir, f"{rid}.analysis.json"), {
                "url": url, "title": title, "_model": self.model_analyze, "_model_status": "skipped",
            })

        # embeddings (for clustering later)
        if self.use_ollama and self.ollama and len(text) > 250:
            try:
                async with self.ollama_sema:
                    vec = await self.ollama.async_embed(self.model_embed, (title + "\n" + text)[:5000], timeout_s=60.0)
                if vec:
                    out_vec = os.path.join(self.embed_dir, f"{rid}.embed.json")
                    with open(out_vec, "w", encoding="utf-8") as f:
                        json.dump({"url": url, "model": self.model_embed, "embedding": vec}, f)
            except (OSError, TypeError, ValueError) as exc:
                print(f"[WARN] embedding write failed for {url}: {exc}")
        return analysis

    def progress_line(self, active: int = 0) -> str:
        remaining = "unlimited"
        if self.deadline is not None:
            remaining = _clock(self.deadline - time.monotonic())
        s = self.stats
        return (f"[PROGRESS] elapsed={_clock(self.elapsed_s())} remaining={remaining}"
                f" round={self.current_round()} rounds_done={s['rounds_completed']}"
                f" discovered={s['urls_discovered']} processed={s['urls_processed']}"
                f" records={s['records_collected']} frontier={len(self.queued)} active={active}")

    def _next_eligible(self) -> Optional[Tuple[str, int]]:
        """Pop the next URL still worth a request, discarding ones policy now rules out."""
        while self.queue:
            u, d = self.queue.popleft()
            self.queued.discard(u)
            if u in self.visited or u in self.in_progress or d > self.max_depth or not self._scoped(u):
                continue
            host = host_of(u)
            if ((self.max_per_host and self.host_pages[host] >= self.max_per_host)
                    or self.host_failures[host] >= HOST_FAILURE_LIMIT):
                self.visited.add(u)
                self.stats["policy_skipped"] += 1
                continue
            self.host_pages[host] += 1  # counted at dispatch so the cap holds under concurrency
            return u, d
        return None

    async def _guarded(self, client: httpx.AsyncClient, u: str, d: int) -> bool:
        try:
            return await self._process_one(client, u, d)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Page-specific parser/analyzer defects must not abort unrelated work.
            self._done(u, "failed")
            print(f"[FAIL] {u} -> unexpected processing error: {exc}")
            return True

    def _requeue(self, u: str, d: int):
        if u not in self.visited and u not in self.queued:
            self.host_pages[host_of(u)] -= 1  # the request was not spent
            self.queue.appendleft((u, d))
            self.queued.add(u)

    async def crawl(self):
        self._session_start = time.monotonic()
        self.deadline = self._session_start + self.runtime_s if self.runtime_s else None
        self.stats["sessions"] += 1
        stop_reason = "frontier_exhausted"
        tasks: Dict[asyncio.Task, Tuple[str, int]] = {}
        last_progress = last_checkpoint = self._session_start

        def settle(done):
            for task in done:
                u, d = tasks.pop(task)
                self.in_progress.discard(u)
                if task.cancelled() or task.exception() is not None or task.result() is False:
                    self._requeue(u, d)

        limits = httpx.Limits(max_connections=self.concurrency * 2, max_keepalive_connections=self.concurrency)
        async with httpx.AsyncClient(limits=limits, trust_env=False) as client:
            try:
                while True:
                    if self._expired():
                        stop_reason = "runtime_expired"
                        break
                    budget_left = len(self.visited) < self.max_urls
                    if not tasks:
                        if not budget_left:
                            stop_reason = "max_urls"
                            break
                        if not self.queue and not self._promote_round():
                            break
                        self._save_state()  # round boundary checkpoint
                        last_checkpoint = time.monotonic()

                    while len(tasks) < self.concurrency and len(self.visited) + len(tasks) < self.max_urls:
                        item = self._next_eligible()
                        if item is None:
                            break
                        self.in_progress.add(item[0])
                        tasks[asyncio.create_task(self._guarded(client, *item))] = item

                    if tasks:
                        timeout = 0.5
                        if self.deadline is not None:
                            timeout = max(0.0, min(timeout, self.deadline - time.monotonic()))
                        done, _ = await asyncio.wait(list(tasks), timeout=timeout,
                                                     return_when=asyncio.FIRST_COMPLETED)
                        settle(done)

                    now = time.monotonic()
                    if self.progress_interval_s and now - last_progress >= self.progress_interval_s:
                        last_progress = now
                        print(self.progress_line(len(tasks)), flush=True)
                    if now - last_checkpoint >= self.checkpoint_interval_s:
                        last_checkpoint = now
                        self._save_state()

                if tasks:
                    # Let in-flight pages finish; at the runtime limit only for a grace period.
                    grace = self.shutdown_grace_s if stop_reason == "runtime_expired" else None
                    done, _ = await asyncio.wait(list(tasks), timeout=grace)
                    settle(done)
            except asyncio.CancelledError:
                stop_reason = "interrupted"
                raise
            finally:
                # Anything still running is cancelled and returned to the frontier.
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                settle(list(tasks))
                if not self.queue and not tasks:
                    self._close_round()
                self.stats["stop_reason"] = stop_reason
                self._save_state()
                print(self.progress_line(), flush=True)
                print(f"[STOP] {stop_reason}: {len(self.queued)} URL(s) left in the frontier"
                      + (" (resumable)" if self.queued else ""), flush=True)

        # Graph is derived from the persisted records so resumed sessions are included.
        nodes_path = os.path.join(self.run_dir, "graph_nodes.jsonl")
        edges_path = os.path.join(self.run_dir, "graph_edges.jsonl")
        for path in (nodes_path, edges_path):
            if os.path.exists(path):
                os.remove(path)
        export_graph(self.run_dir, read_jsonl(self.page_scores_jsonl),
                     {row.get("url"): row for row in read_jsonl(self.indicators_jsonl)})

        return {
            "urls_jsonl": self.urls_jsonl,
            "indicators_jsonl": self.indicators_jsonl,
            "page_scores_jsonl": self.page_scores_jsonl,
            "hunt_jsonl": self.hunt_jsonl,
            "graph_nodes": nodes_path,
            "graph_edges": edges_path,
            "discovery_edges": self.edges_jsonl,
            "crawl_stats": self.stats_path,
            "stop_reason": stop_reason,
            "frontier_remaining": len(self.queued),
            "stats": self.stats,
        }
