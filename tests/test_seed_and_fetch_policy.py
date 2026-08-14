import os
import sys
import tempfile
import unittest

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from osintai.cli import _resolve_seed_urls, _validate_run_id  # noqa: E402
from osintai.crawler import AsyncCrawler  # noqa: E402
from osintai.extractor import Extractor  # noqa: E402
from osintai.fetcher import AsyncFetcher, FetchRejected  # noqa: E402


class SeedInputTests(unittest.TestCase):
    def test_explicit_seed_file_is_loaded_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "seeds.txt")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("# targets\nhttps://one.test/\nhttps://two.test/\nhttps://one.test/\n")
            self.assertEqual(
                _resolve_seed_urls(None, path, directory),
                ["https://one.test/", "https://two.test/"],
            )

    def test_file_passed_as_seed_gets_actionable_error(self):
        with tempfile.NamedTemporaryFile() as handle:
            with self.assertRaisesRegex(ValueError, "--seed-file"):
                _resolve_seed_urls([handle.name], None, os.getcwd())

    def test_same_domain_scope_accepts_every_seed_host_only(self):
        crawler = object.__new__(AsyncCrawler)
        crawler.same_domain_only = True
        crawler.allowed_seed_hosts = {"one.test", "two.test"}
        self.assertTrue(crawler._scoped("https://one.test/page"))
        self.assertTrue(crawler._scoped("https://two.test/page"))
        self.assertFalse(crawler._scoped("https://outside.test/page"))
        self.assertFalse(crawler._scoped("ftp://one.test/archive"))
        self.assertFalse(crawler._scoped("https://user:secret@one.test/private"))

    def test_seed_urls_reject_embedded_credentials(self):
        with self.assertRaisesRegex(ValueError, "invalid HTTP\\(S\\) seed URL"):
            _resolve_seed_urls(["https://user:secret@one.test/"], None, os.getcwd())

    def test_run_id_cannot_escape_the_run_directory(self):
        for value in ("../outside", "nested/run", "/absolute", "..", ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _validate_run_id(value)
        self.assertEqual(_validate_run_id("case-2026.08_14"), "case-2026.08_14")


class ExtractorSafetyTests(unittest.TestCase):
    def test_malformed_ipv6_like_url_is_discarded_without_crashing(self):
        indicators = Extractor().extract_indicators(
            "https://one.test/",
            "Malformed evidence URL: http://[not-an-ipv6/path and https://valid.test/report.",
            "",
        )
        self.assertEqual(indicators["urls"], ["https://valid.test/report"])
        self.assertIn("valid.test", indicators["domains"])


class FetchPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_html_within_limit_is_returned(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"content-type": "text/html"}, text="<html>safe</html>"
            )
        )
        fetcher = AsyncFetcher([], min_delay_s=0, max_delay_s=0, max_response_bytes=100)
        async with httpx.AsyncClient(transport=transport) as client:
            response = await fetcher.get(client, "https://one.test/")
        self.assertEqual(response.text, "<html>safe</html>")

    async def test_binary_content_is_rejected(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"content-type": "application/zip"}, content=b"PK"
            )
        )
        fetcher = AsyncFetcher([], min_delay_s=0, max_delay_s=0)
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaisesRegex(FetchRejected, "not HTML/XHTML"):
                await fetcher.get(client, "https://one.test/archive.zip")

    async def test_oversized_html_is_rejected(self):
        transport = httpx.MockTransport(
            lambda request: httpx.Response(
                200, headers={"content-type": "text/html"}, content=b"x" * 11
            )
        )
        fetcher = AsyncFetcher([], min_delay_s=0, max_delay_s=0, max_response_bytes=10)
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaisesRegex(FetchRejected, "byte limit"):
                await fetcher.get(client, "https://one.test/")

    async def test_out_of_scope_redirect_is_rejected_before_request(self):
        requested = []

        def handler(request):
            requested.append(str(request.url))
            return httpx.Response(302, headers={"location": "https://outside.test/secret"})

        transport = httpx.MockTransport(handler)
        fetcher = AsyncFetcher([], min_delay_s=0, max_delay_s=0)
        validator = lambda url: httpx.URL(url).host == "one.test"
        async with httpx.AsyncClient(transport=transport) as client:
            with self.assertRaisesRegex(FetchRejected, "outside authorized scope"):
                await fetcher.get(
                    client, "https://one.test/", redirect_validator=validator
                )
        self.assertEqual(requested, ["https://one.test/"])

    async def test_in_scope_redirect_is_followed(self):
        requested = []

        def handler(request):
            requested.append(str(request.url))
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/final"})
            return httpx.Response(
                200, headers={"content-type": "text/html"}, text="<html>ok</html>"
            )

        transport = httpx.MockTransport(handler)
        fetcher = AsyncFetcher([], min_delay_s=0, max_delay_s=0)
        validator = lambda url: httpx.URL(url).host == "one.test"
        async with httpx.AsyncClient(transport=transport) as client:
            response = await fetcher.get(
                client, "https://one.test/", redirect_validator=validator
            )
        self.assertEqual(str(response.url), "https://one.test/final")
        self.assertEqual(requested, ["https://one.test/", "https://one.test/final"])


class OllamaEndpointTests(unittest.TestCase):
    def test_ollama_endpoint_is_loopback_only(self):
        from osintai.ollama_api import OllamaAPI

        self.assertEqual(OllamaAPI("http://127.0.0.1:11434").base_url, "http://127.0.0.1:11434")
        self.assertEqual(OllamaAPI("http://[::1]:11434").base_url, "http://[::1]:11434")
        for value in (
            "https://models.example/api",
            "http://192.168.1.10:11434",
            "http://user:pass@localhost:11434",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                OllamaAPI(value)


if __name__ == "__main__":
    unittest.main()
