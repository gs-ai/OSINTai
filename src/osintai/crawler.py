import os
import json
import time
import asyncio
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Set, Optional
from urllib.parse import urlparse

import httpx

from .normalize import clean_url, same_domain
from .storage import sha1, safe_mkdir, append_jsonl, read_json, write_json
from .extractor import Extractor
from .fetcher import AsyncFetcher
from .proxy_pool import ProxyPool
from .ollama_api import OllamaAPI
from .dedupe import sha1_text, simhash_64, hamming64
from .analyzer import compute_page_signal
from .hunt import hunt_leads
from .graph_export import export_graph

def is_probably_html(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("content-type", "") or ""
    return ("text/html" in ctype) or ("application/xhtml+xml" in ctype) or (ctype.strip() == "")

def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except:
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
        hunt_max_leads: int
    ):
        self.seed_urls = seed_urls
        self.primary_seed = seed_urls[0] if seed_urls else ""  # For same_domain comparison
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
        self.queue: List[Tuple[str, int]] = [(url, 0) for url in seed_urls]
        self.indicators_by_url: Dict[str, Dict] = {}
        self.pages_scored: List[Dict] = []

        # near-duplicate tracking by simhash
        self.simhash_seen: List[int] = []

        # host semaphores
        self.host_sema: Dict[str, asyncio.Semaphore] = {}

        self.ollama = OllamaAPI() if self.use_ollama else None

        if self.resume:
            self._load_state()

    def _load_state(self):
        st = read_json(self.state_path, default=None)
        if st:
            self.visited = set(st.get("visited", []))
            self.queue = [tuple(x) for x in st.get("queue", [])]
            self.simhash_seen = st.get("simhash_seen", [])[:5000]
            if not self.queue:
                self.queue = [(self.seed_url, 0)]

    def _save_state(self):
        write_json(self.state_path, {
            "visited": sorted(self.visited),
            "queue": self.queue[:20000],
            "simhash_seen": self.simhash_seen[:5000]
        })

        # proxy pool snapshot if present
        if getattr(self.fetcher, "proxy_pool", None):
            try:
                write_json(self.proxy_state, self.fetcher.proxy_pool.as_dict())
            except:
                pass

    def _host_lock(self, url: str) -> asyncio.Semaphore:
        h = host_of(url)
        if h not in self.host_sema:
            self.host_sema[h] = asyncio.Semaphore(self.per_host_concurrency)
        return self.host_sema[h]

    def _scoped(self, url: str) -> bool:
        if not url:
            return False
        if self.same_domain_only and not same_domain(url, self.primary_seed):
            return False
        return True

    def _dedupe_near(self, text: str) -> Tuple[bool, int]:
        sh = simhash_64(text)
        # if very close to any prior simhash, drop it
        for prev in self.simhash_seen[-400:]:
            if hamming64(sh, prev) <= 3:
                return True, sh
        self.simhash_seen.append(sh)
        return False, sh

    def _analysis_prompt(self, url: str, title: str, text: str) -> str:
        snippet = (text or "")[:12000]
        return f"""
You are an OSINT analyst. Produce a structured intelligence extraction from this webpage.

Rules:
- No filler. No moralizing.
- Only use evidence from the content.
- Output valid JSON only.

Return schema:
{{
  "url": "...",
  "title": "...",
  "summary": "2-4 sentences",
  "key_entities": ["..."],
  "key_locations": ["..."],
  "key_dates": ["..."],
  "keywords": ["..."],
  "risk_flags": ["..."],
  "actionable_leads": ["..."]
}}

URL: {url}
TITLE: {title}

CONTENT:
{snippet}
""".strip()

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
                resp = await self.fetcher.get(client, url)
            except Exception as e:
                print(f"[FAIL] {url} -> {e}")
                return

        status = resp.status_code
        if status != 200 or not is_probably_html(resp):
            self.visited.add(url)
            print(f"[SKIP] {status} {url}")
            return

        html = resp.text
        title, text = self.extractor.html_to_text(html)

        # near-dup check
        is_near_dup, sh = self._dedupe_near(text)
        if is_near_dup:
            self.visited.add(url)
            print(f"[DUP]  depth={depth:02d} {url}")
            return

        out_links = self.extractor.extract_links(url, html)
        for lk in out_links:
            lk = clean_url(lk)
            if lk and lk not in self.visited and self._scoped(lk):
                self.queue.append((lk, depth + 1))

        rid = sha1(url)
        raw_path = os.path.join(self.raw_dir, f"{rid}.html")
        text_path = os.path.join(self.text_dir, f"{rid}.txt")

        with open(raw_path, "w", encoding="utf-8", errors="ignore") as f:
            f.write(html)
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

        indicators = self.extractor.extract_indicators(url, text, html)
        self.indicators_by_url[url] = indicators
        append_jsonl(self.indicators_jsonl, indicators)

        analysis = {}
        if self.use_ollama and self.ollama and len(text) > 250:
            prompt = self._analysis_prompt(url, title, text)
            try:
                analysis = self.ollama.generate_json(self.model_analyze, prompt, timeout_s=140.0)
            except Exception as e:
                analysis = {"url": url, "title": title, "error": "ollama_generate_failed", "exception": str(e)}

            out_json = os.path.join(self.analysis_dir, f"{rid}.analysis.json")
            with open(out_json, "w", encoding="utf-8") as f:
                json.dump(analysis, f, ensure_ascii=False, indent=2)

        # embeddings (for clustering later)
        if self.use_ollama and self.ollama and len(text) > 250:
            try:
                vec = self.ollama.embed(self.model_embed, (title + "\n" + text)[:5000], timeout_s=60.0)
                if vec:
                    out_vec = os.path.join(self.embed_dir, f"{rid}.embed.json")
                    with open(out_vec, "w", encoding="utf-8") as f:
                        json.dump({"url": url, "model": self.model_embed, "embedding": vec}, f)
            except:
                pass

        # hunt mode on every page (lightweight)
        hunt = hunt_leads(text, self.hunt_terms, max_leads=self.hunt_max_leads) if self.hunt_terms else {"hits": [], "lead_urls": []}
        if hunt.get("hits") or hunt.get("lead_urls"):
            append_jsonl(self.hunt_jsonl, {"url": url, "depth": depth, **hunt})
            for u in hunt.get("lead_urls", [])[: self.hunt_max_leads]:
                u2 = clean_url(u)
                if u2 and u2 not in self.visited and self._scoped(u2):
                    self.queue.append((u2, depth + 1))

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
        async with httpx.AsyncClient(limits=limits) as client:
            sem = asyncio.Semaphore(self.concurrency)

            async def worker(u: str, d: int):
                async with sem:
                    await self._process_one(client, u, d)

            while self.queue and len(self.visited) < self.max_urls:
                batch = []
                # Pull a batch
                while self.queue and len(batch) < (self.concurrency * 2) and len(self.visited) + len(batch) < self.max_urls:
                    u, d = self.queue.pop(0)
                    u = clean_url(u)
                    if not u or u in self.visited:
                        continue
                    if d > self.max_depth:
                        continue
                    if not self._scoped(u):
                        continue
                    batch.append((u, d))

                if not batch:
                    await asyncio.sleep(0.05)
                    continue

                await asyncio.gather(*[worker(u, d) for (u, d) in batch])

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
        self.queue: List[Tuple[str, int]] = [(seed_url, 0)]

        if resume:
            self._load_state()

    def _load_state(self):
        st = read_json(self.state_path, default=None)
        if not st:
            return
        self.visited = set(st.get("visited", []))
        self.queue = [tuple(x) for x in st.get("queue", [])]
        if not self.queue:
            self.queue = [(self.seed_url, 0)]

    def _save_state(self):
        write_json(self.state_path, {"visited": sorted(self.visited), "queue": self.queue})

    def crawl_sync(self):
        while self.queue and len(self.visited) < self.max_urls:
            url, depth = self.queue.pop(0)
            url = clean_url(url)
            if not url:
                continue

            if url in self.visited:
                continue
            if depth > self.max_depth:
                continue

            if self.same_domain_only and not same_domain(url, self.primary_seed):
                continue

            try:
                resp = self.fetcher.get(url)
                status = resp.status_code

                if status != 200 or not is_probably_html(resp):
                    self.visited.add(url)
                    print(f"[SKIP] {status} {url}")
                    self._save_state()
                    continue

                html = resp.text
                title, text = self.extractor.html_to_text(html)

                out_links = self.extractor.extract_links(url, html)
                for lk in out_links:
                    if lk not in self.visited:
                        self.queue.append((lk, depth + 1))

                rid = sha1(url)
                raw_path = os.path.join(self.raw_dir, f"{rid}.html")
                text_path = os.path.join(self.text_dir, f"{rid}.txt")

                with open(raw_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(html)
                with open(text_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(text)

                page = PageRecord(
                    url=url,
                    status_code=status,
                    fetched_at=time.time(),
                    content_sha1=sha1(html),
                    title=title[:200],
                    text_len=len(text),
                    out_links_count=len(out_links),
                    saved_raw_path=raw_path,
                    saved_text_path=text_path
                )

                append_jsonl(self.urls_jsonl, asdict(page))
                self.visited.add(url)

                indicators = self.extractor.extract_indicators(url, text, html)
                append_jsonl(self.indicators_jsonl, indicators)

                analysis = {}
                if self.ollama and len(text) > 200:
                    analysis = self.ollama.analyze(url, title, text)
                    out_json = os.path.join(self.analysis_dir, f"{rid}.analysis.json")
                    with open(out_json, "w", encoding="utf-8") as f:
                        import json
                        json.dump(analysis, f, ensure_ascii=False, indent=2)

                score = compute_page_signal(indicators, analysis if isinstance(analysis, dict) else {})
                scored = {
                    "url": url,
                    "title": page.title,
                    "score": score,
                    "summary": analysis.get("summary") if isinstance(analysis, dict) else "",
                    "risk_flags": analysis.get("risk_flags") if isinstance(analysis, dict) else []
                }
                append_jsonl(self.page_scores_path, scored)

                print(f"[OK] depth={depth:02d} links={len(out_links):03d} score={score:05.2f} text={len(text):05d}  {url}")
                self._save_state()

            except Exception as e:
                print(f"[FAIL] {url}  -> {e}")
                self._save_state()

        return {
            "urls_jsonl": self.urls_jsonl,
            "indicators_jsonl": self.indicators_jsonl,
            "page_scores_jsonl": self.page_scores_jsonl,
            "hunt_jsonl": self.hunt_jsonl,
            "graph_nodes": os.path.join(self.run_dir, "graph_nodes.jsonl"),
            "graph_edges": os.path.join(self.run_dir, "graph_edges.jsonl")
        }
