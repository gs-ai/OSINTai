import os
import json
import time
import asyncio
from collections import deque
from dataclasses import dataclass, asdict
from typing import Deque, Dict, List, Tuple, Set
from urllib.parse import urlparse

import httpx

from .normalize import clean_url
from .storage import sha1, safe_mkdir, append_jsonl, read_json, write_json
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

def _extract_page(extractor, url, html, hunt_terms, hunt_limit):
    title, text = extractor.html_to_text(html)
    return (title, text, extractor.extract_links(url, html),
            extractor.extract_indicators(url, text, html),
            hunt_leads(text, hunt_terms, max_leads=hunt_limit), simhash_64(text))


class AsyncCrawler:
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
        extraction_timeout_s: float = 30.0
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

        self.use_ollama = use_ollama
        self.model_analyze = model_analyze
        self.model_embed = model_embed

        self.hunt_terms = hunt_terms
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
        self.state_path = os.path.join(run_dir, "crawl_state.json")
        self.proxy_state = os.path.join(run_dir, "proxy_pool.json")

        self.visited: Set[str] = set()
        self.queue: Deque[Tuple[str, int]] = deque()
        self.queued: Set[str] = set()
        self.in_progress: Set[str] = set()
        self.indicators_by_url: Dict[str, Dict] = {}
        self.pages_scored: List[Dict] = []

        # near-duplicate tracking by simhash
        self.simhash_seen: List[int] = []

        # host semaphores
        self.host_sema: Dict[str, asyncio.Semaphore] = {}
        self.ollama_sema = asyncio.Semaphore(max(1, min(2, self.concurrency)))

        self.ollama = OllamaAPI() if self.use_ollama else None
        for url in seed_urls:
            self._enqueue(url, 0)

        if self.resume:
            self._load_state()

    def _load_state(self):
        st = read_json(self.state_path, default=None)
        if not st:
            return

        self.visited = set(st.get("visited", []))
        self.queue.clear()
        self.queued.clear()
        self.in_progress.clear()
        self.simhash_seen = st.get("simhash_seen", [])[:5000]

        for item in st.get("queue", []):
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            url, depth = item
            self._enqueue(url, int(depth))

        if not self.queue:
            for url in self.seed_urls:
                self._enqueue(url, 0)

    def _save_state(self):
        write_json(self.state_path, {
            "visited": sorted(self.visited),
            "queue": list(self.queue)[:20000],
            "simhash_seen": self.simhash_seen[:5000]
        })

        # proxy pool snapshot if present
        if getattr(self.fetcher, "proxy_pool", None):
            try:
                write_json(self.proxy_state, self.fetcher.proxy_pool.as_dict())
            except (OSError, TypeError, ValueError) as exc:
                print(f"[WARN] could not save proxy state: {exc}")

    def _enqueue(self, url: str, depth: int) -> bool:
        url = clean_url(url)
        if not url or depth > self.max_depth:
            return False
        if url in self.visited or url in self.queued or url in self.in_progress:
            return False
        if not self._scoped(url):
            return False
        self.queue.append((url, depth))
        self.queued.add(url)
        return True

    def _host_lock(self, url: str) -> asyncio.Semaphore:
        h = host_of(url)
        if h not in self.host_sema:
            self.host_sema[h] = asyncio.Semaphore(self.per_host_concurrency)
        return self.host_sema[h]

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
        return False, sh

    def _analysis_prompt(self, url: str, title: str, text: str) -> str:
        # Delegates to the prompt registry. The 'standard' profile is the same text this
        # method has always produced, so osint-tuned-v3 sees identical input.
        return page_prompt(url, title, text, self.prompt_profile)

    async def _process_one(self, client: httpx.AsyncClient, url: str, depth: int):
        url = clean_url(url)
        if not url or url in self.visited:
            return
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_urls:
            return
        if not self._scoped(url):
            return

        lock = self._host_lock(url)
        async with lock:
            try:
                resp = await self.fetcher.get(client, url, redirect_validator=self._scoped)
            except FetchRejected as e:
                self.visited.add(url)
                print(f"[SKIP] {url} -> {e}")
                return
            except Exception as e:
                print(f"[FAIL] {url} -> {e}")
                return

        requested_url = url
        final_url = clean_url(str(resp.url))
        if not final_url or not self._scoped(final_url):
            self.visited.add(url)
            print(f"[SKIP] redirect outside seed domains: {url} -> {final_url}")
            return
        if final_url != requested_url:
            self.visited.add(requested_url)
        url = final_url
        status = resp.status_code
        if status != 200 or not is_probably_html(resp):
            self.visited.add(url)
            print(f"[SKIP] {status} {url}")
            return

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
            self.visited.add(url)
            print(f"[FAIL] extraction {url}: {exc}")
            return

        # near-dup check
        is_near_dup, sh = self._dedupe_near(text, sh)
        if is_near_dup:
            self.visited.add(url)
            print(f"[DUP]  depth={depth:02d} {url}")
            return

        for lk in out_links:
            self._enqueue(lk, depth + 1)

        rid = sha1(url)
        raw_path = os.path.join(self.raw_dir, f"{rid}.html")
        text_path = os.path.join(self.text_dir, f"{rid}.txt")

        with open(text_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(text)

        page = PageRecord(
            url=url,
            status_code=status,
            fetched_at=time.time(),
            content_sha1=sha1_text(html),
            title=(title or "")[:200],
            text_len=len(text),
            out_links_count=len(out_links),
            saved_raw_path=raw_path,
            saved_text_path=text_path,
            simhash64=sh
        )
        append_jsonl(self.urls_jsonl, asdict(page))

        self.indicators_by_url[url] = indicators
        append_jsonl(self.indicators_jsonl, indicators)

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

        # hunt mode on every page (lightweight)
        if hunt.get("hits") or hunt.get("lead_urls"):
            append_jsonl(self.hunt_jsonl, {"url": url, "depth": depth, **hunt})
            for u in hunt.get("lead_urls", [])[: self.hunt_max_leads]:
                self._enqueue(u, depth + 1)

        score = compute_page_signal(indicators, analysis if isinstance(analysis, dict) else {})
        scored = {
            "url": url,
            "title": page.title,
            "score": score,
            "summary": analysis.get("summary") if isinstance(analysis, dict) else "",
            "risk_flags": analysis.get("risk_flags") if isinstance(analysis, dict) else []
        }
        self.pages_scored.append(scored)
        append_jsonl(self.page_scores_jsonl, scored)

        self.visited.add(url)
        print(f"[OK] depth={depth:02d} links={len(out_links):03d} score={score:05.2f} text={len(text):05d} {url}")

    async def crawl(self):
        limits = httpx.Limits(max_connections=self.concurrency * 2, max_keepalive_connections=self.concurrency)
        async with httpx.AsyncClient(limits=limits, trust_env=False) as client:
            sem = asyncio.Semaphore(self.concurrency)

            async def worker(u: str, d: int):
                async with sem:
                    try:
                        await self._process_one(client, u, d)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        # Page-specific parser/analyzer defects must not abort
                        # unrelated work in the same concurrent batch.
                        self.visited.add(u)
                        print(f"[FAIL] {u} -> unexpected processing error: {exc}")

            while self.queue and len(self.visited) < self.max_urls:
                batch = []
                # Pull a batch
                while self.queue and len(batch) < (self.concurrency * 2) and len(self.visited) + len(batch) < self.max_urls:
                    u, d = self.queue.popleft()
                    self.queued.discard(u)
                    u = clean_url(u)
                    if not u or u in self.visited or u in self.in_progress:
                        continue
                    if d > self.max_depth:
                        continue
                    if not self._scoped(u):
                        continue
                    self.in_progress.add(u)
                    batch.append((u, d))

                if not batch:
                    await asyncio.sleep(0.05)
                    continue

                try:
                    await asyncio.gather(*[worker(u, d) for (u, d) in batch])
                finally:
                    for u, _ in batch:
                        self.in_progress.discard(u)

                # checkpoint
                self._save_state()

        # Export graph at end
        export_graph(self.run_dir, self.pages_scored, self.indicators_by_url)

        return {
            "urls_jsonl": self.urls_jsonl,
            "indicators_jsonl": self.indicators_jsonl,
            "page_scores_jsonl": self.page_scores_jsonl,
            "hunt_jsonl": self.hunt_jsonl,
            "graph_nodes": os.path.join(self.run_dir, "graph_nodes.jsonl"),
            "graph_edges": os.path.join(self.run_dir, "graph_edges.jsonl"),
        }
