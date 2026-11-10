import asyncio
import contextlib
import hashlib
import io
import os
import sys
import tempfile
import time
import unittest
from collections import Counter

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from osintai.cli import _parse_runtime, _prompt_runtime, _prompt_start_url  # noqa: E402
from osintai.crawler import AsyncCrawler  # noqa: E402
from osintai.extractor import Extractor  # noqa: E402
from osintai.fetcher import AsyncFetcher  # noqa: E402
from osintai.normalize import canonical_url  # noqa: E402
from osintai.storage import read_json, read_jsonl  # noqa: E402

WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima mike "
         "november oscar papa quebec romeo sierra tango uniform victor whiskey xray yankee "
         "zulu amber birch cedar dune ember fjord grove heath inlet jetty knoll ledge").split()


def page(name: str, links) -> str:
    """Distinct body text per page so near-duplicate suppression does not interfere."""
    seed = int(hashlib.sha256(name.encode()).hexdigest()[:12], 16)
    body = " ".join(f"{WORDS[(seed + i * 7) % len(WORDS)]}{seed + i * 7919}" for i in range(40))
    anchors = "".join(f'<a href="{href}">link</a>' for href in links)
    return f"<html><head><title>{name}</title></head><body><p>{body}</p>{anchors}</body></html>"


class SiteFetcher(AsyncFetcher):
    """The real fetch policy, served from an in-memory site instead of the network."""

    def __init__(self, handler):
        super().__init__([], min_delay_s=0, max_delay_s=0, retries=0)
        self.requested = []

        async def recording(request):
            self.requested.append(str(request.url))
            result = handler(request)
            return await result if asyncio.iscoroutine(result) else result

        self.site = httpx.AsyncClient(transport=httpx.MockTransport(recording))

    async def get(self, client, url, redirect_validator=None):
        return await super().get(self.site, url, redirect_validator)


def html(text: str) -> httpx.Response:
    return httpx.Response(200, headers={"content-type": "text/html"}, text=text)


def static_site(pages):
    def handler(request):
        key = request.url.path + (f"?{request.url.query.decode()}" if request.url.query else "")
        if key not in pages:
            return httpx.Response(404)
        return html(page(key, pages[key]))
    return handler


def endless_site(delay_s=0.02):
    """Every page links to three pages that do not exist yet: unbounded growth."""
    async def handler(request):
        await asyncio.sleep(delay_s)
        base = request.url.path.rstrip("/")
        return html(page(request.url.path, [f"{base}/{i}" for i in range(3)]))
    return handler


class ExpansionCase(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = self.tmp.name
        self.fetchers = []

    async def asyncTearDown(self):
        for fetcher in self.fetchers:
            await fetcher.site.aclose()

    def crawler(self, handler, seed="https://site.test/", **overrides):
        fetcher = SiteFetcher(handler)
        self.fetchers.append(fetcher)
        options = dict(
            seed_urls=[seed], max_depth=1_000_000, max_urls=10_000, run_dir=self.run_dir,
            fetcher=fetcher, extractor=Extractor(), same_domain_only=False, resume=True,
            concurrency=8, per_host_concurrency=8, use_ollama=False, model_analyze="",
            model_embed="", hunt_terms=[], hunt_max_leads=10, progress_interval_s=0,
            checkpoint_interval_s=0.2, shutdown_grace_s=0.5,
        )
        options.update(overrides)
        return AsyncCrawler(**options), fetcher

    async def run_quiet(self, crawler):
        with contextlib.redirect_stdout(io.StringIO()):
            return await crawler.crawl()

    def records(self):
        return read_jsonl(os.path.join(self.run_dir, "urls_crawled.jsonl"))


class RecursiveDiscoveryTests(ExpansionCase):
    async def test_each_round_expands_from_the_previous_rounds_discoveries(self):
        site = {
            "/": ["/b", "/c"],
            "/b": ["/d"],
            "/c": ["/"],            # loop back to the seed
            "/d": ["/e", "/b"],     # loop back up the tree
            "/e": [],
        }
        crawler, fetcher = self.crawler(static_site(site))
        out = await self.run_quiet(crawler)

        self.assertEqual(out["stop_reason"], "frontier_exhausted")
        self.assertEqual(out["frontier_remaining"], 0)
        self.assertEqual(sorted(fetcher.requested),
                         sorted(f"https://site.test{path}" for path in site))
        stats = out["stats"]
        self.assertEqual(stats["rounds_completed"], 4)
        self.assertEqual(stats["urls_discovered"], 5)
        self.assertEqual(stats["urls_processed"], 5)
        self.assertEqual(stats["records_collected"], 5)
        self.assertEqual([r["urls_processed"] for r in stats["rounds"]], [1, 2, 1, 1])

        by_url = {row["url"]: row for row in self.records()}
        leaf = by_url["https://site.test/e"]
        self.assertEqual(leaf["depth"], 3)
        self.assertEqual(leaf["round"], 4)
        self.assertEqual(leaf["parent_url"], "https://site.test/d")
        self.assertEqual(leaf["discovery_path"], [
            "https://site.test/", "https://site.test/b",
            "https://site.test/d", "https://site.test/e",
        ])
        self.assertTrue(leaf["fetched_at_utc"].endswith("Z"))

        edges = read_jsonl(os.path.join(self.run_dir, "discovery_edges.jsonl"))
        self.assertEqual(
            {(e["parent"], e["child"], e["via"]) for e in edges},
            {("", "https://site.test/", "seed"),
             ("https://site.test/", "https://site.test/b", "link"),
             ("https://site.test/", "https://site.test/c", "link"),
             ("https://site.test/b", "https://site.test/d", "link"),
             ("https://site.test/d", "https://site.test/e", "link")},
        )
        self.assertTrue(os.path.exists(out["graph_nodes"]))

    async def test_depth_limit_still_bounds_expansion(self):
        crawler, fetcher = self.crawler(endless_site(0), max_depth=2)
        out = await self.run_quiet(crawler)
        self.assertEqual(out["stop_reason"], "frontier_exhausted")
        self.assertEqual(len(fetcher.requested), 1 + 3 + 9)


class DeduplicationTests(ExpansionCase):
    def test_canonical_url_collapses_equivalent_forms(self):
        expected = "https://site.test/a?x=1&y=2"
        for variant in (
            "https://site.test/a?x=1&y=2",
            "HTTPS://SITE.TEST:443/a?y=2&x=1#section",
            "https://site.test/a?utm_source=mail&y=2&x=1&fbclid=abc",
            "https://site.test./a?x=1&y=2&PHPSESSID=deadbeef",
        ):
            self.assertEqual(canonical_url(variant), expected)
        self.assertEqual(canonical_url("https://site.test"), "https://site.test/")
        self.assertEqual(canonical_url("http://site.test:8080/"), "http://site.test:8080/")
        self.assertIsNone(canonical_url("mailto:person@site.test"))
        # Credentials are left visible so the scope policy rejects them.
        self.assertEqual(canonical_url("https://u:p@site.test/"), "https://u:p@site.test/")

    async def test_equivalent_links_are_requested_once(self):
        site = {
            "/": ["/a", "/a#top", "/a?utm_campaign=x", "HTTPS://SITE.TEST:443/a",
                  "/b", "mailto:x@site.test", "/logo.png", "/report.pdf"],
            "/a": ["/", "/b?fbclid=1", "/a"],
            "/b": ["/a#x"],
        }
        crawler, fetcher = self.crawler(static_site(site))
        out = await self.run_quiet(crawler)
        self.assertEqual(Counter(fetcher.requested), Counter({
            "https://site.test/": 1, "https://site.test/a": 1, "https://site.test/b": 1,
        }))
        self.assertEqual(out["stats"]["urls_discovered"], 3)

    async def test_frontier_and_per_host_budgets_are_enforced(self):
        crawler, fetcher = self.crawler(endless_site(0), max_frontier=12, max_per_host=25)
        peak = 0
        accept = crawler._accept

        def tracking(*args):
            nonlocal peak
            accepted = accept(*args)
            peak = max(peak, len(crawler.queued))
            return accepted

        crawler._accept = tracking
        out = await self.run_quiet(crawler)
        self.assertLessEqual(peak, 12)
        self.assertGreater(out["stats"]["frontier_dropped"], 0)
        self.assertLessEqual(len(fetcher.requested), 25)
        self.assertEqual(out["stop_reason"], "frontier_exhausted")

    async def test_throttled_host_is_backed_off(self):
        crawler, _ = self.crawler(lambda request: httpx.Response(429, headers={"retry-after": "7"}))
        await self.run_quiet(crawler)
        self.assertEqual(crawler.host_backoff["site.test"], 7.0)
        self.assertEqual(crawler.stats["skipped"], 1)


class RuntimeAndPersistenceTests(ExpansionCase):
    async def test_runtime_limit_stops_and_checkpoints_then_resumes(self):
        crawler, first = self.crawler(endless_site(), runtime_s=1.5)
        started = time.monotonic()
        out = await self.run_quiet(crawler)
        wall = time.monotonic() - started

        self.assertEqual(out["stop_reason"], "runtime_expired")
        self.assertGreaterEqual(wall, 1.5)
        self.assertLess(wall, 1.5 + 0.5 + 3.0)  # runtime + grace + slack
        self.assertGreater(out["frontier_remaining"], 0)
        self.assertGreater(out["stats"]["rounds_completed"], 1)

        state = read_json(os.path.join(self.run_dir, "crawl_state.json"))
        frontier = {item[0] for item in state["queue"]} | {item[0] for item in state["pending"]}
        self.assertEqual(len(frontier), out["frontier_remaining"])
        self.assertFalse(frontier & set(state["visited"]))
        self.assertEqual(state["seed_urls"], ["https://site.test/"])
        stats = read_json(os.path.join(self.run_dir, "crawl_stats.json"))
        self.assertTrue(stats["resumable"])
        self.assertEqual(stats["stop_reason"], "runtime_expired")
        first_records = self.records()
        self.assertEqual(len(first_records), stats["records_collected"])
        self.assertEqual(set(state["visited"]), {row["url"] for row in first_records})

        # A new process picks the frontier back up without repeating finished work.
        resumed, second = self.crawler(endless_site(), runtime_s=1.0)
        self.assertEqual(resumed.visited, set(state["visited"]))
        self.assertEqual(resumed.queued, frontier)
        out2 = await self.run_quiet(resumed)

        self.assertEqual(out2["stats"]["sessions"], 2)
        self.assertTrue(second.requested)
        # Finished work is never repeated; only pages cut off in flight are fetched again.
        self.assertFalse(set(state["visited"]) & set(second.requested))
        self.assertEqual(len(second.requested), len(set(second.requested)))
        urls = [row["url"] for row in self.records()]
        self.assertEqual(len(urls), len(set(urls)))
        self.assertGreater(len(urls), len(first_records))
        self.assertGreaterEqual(out2["stats"]["elapsed_s"], 2.5)
        # Provenance survives the restart: every path still starts at the seed.
        for row in self.records():
            self.assertEqual(row["discovery_path"][0], "https://site.test/")
            self.assertEqual(row["discovery_path"][-1], row["url"])
            self.assertEqual(len(row["discovery_path"]), row["depth"] + 1)

    async def test_in_flight_pages_are_requeued_at_the_deadline(self):
        async def slow(request):
            await asyncio.sleep(30)
            return html(page("slow", []))

        crawler, _ = self.crawler(slow, runtime_s=0.3, shutdown_grace_s=0.2)
        started = time.monotonic()
        out = await self.run_quiet(crawler)
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(out["stop_reason"], "runtime_expired")
        self.assertEqual(out["frontier_remaining"], 1)
        self.assertEqual(self.records(), [])
        state = read_json(os.path.join(self.run_dir, "crawl_state.json"))
        self.assertEqual(state["queue"], [["https://site.test/", 0]])

    async def test_progress_reports_the_required_counters(self):
        crawler, _ = self.crawler(static_site({"/": ["/b"], "/b": []}), runtime_s=60)
        await self.run_quiet(crawler)
        line = crawler.progress_line()
        for field in ("elapsed=00:00:0", "remaining=00:", "rounds_done=2", "discovered=2",
                      "processed=2", "records=2", "frontier=0"):
            self.assertIn(field, line)


class RuntimePromptTests(unittest.TestCase):
    def test_runtime_window_is_one_to_360_minutes(self):
        self.assertEqual(_parse_runtime("1"), 1.0)
        self.assertEqual(_parse_runtime("360"), 360.0)
        for value in ("0", "0.5", "361", "-5", "nan", "inf", "soon", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _parse_runtime(value)

    def test_prompts_repeat_until_input_is_valid(self):
        answers = iter(["", "ftp://site.test/", "site.test/start"])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(_prompt_start_url(lambda _: next(answers)), "https://site.test/start")
            answers = iter(["abc", "900", "45"])
            self.assertEqual(_prompt_runtime(lambda _: next(answers)), 45.0)
            with self.assertRaises(ValueError):
                _prompt_runtime(lambda _: "0", attempts=2)


if __name__ == "__main__":
    unittest.main()
