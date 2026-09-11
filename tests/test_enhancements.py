"""Offline acceptance tests for containment, resumption, provenance and publication."""

import asyncio
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osintai.checkpoints import ExtractionCache, extract_checkpoint
from osintai.correlation import correlate
from osintai.entities import EntityIndex
from osintai.extractor import Extractor
from osintai.hunt import hunt_leads
from osintai.isolation import isolated_call, async_isolated_call
from osintai.model_quality import page_status
from osintai.ollama_api import OllamaAPI
import httpx
from osintai.model_retry import retry_saved
from osintai.pipeline import AnalysisOptions, RunArtifacts, analyze_run
from osintai.publication import retry_source_hashes, source_hashes
from osintai.storage import sha1, sync_file, write_json
from osintai.scanners import credentials


def busy_worker():
    while True:
        pass


def crash_worker():
    os._exit(7)


def large_result():
    return "x" * 2_000_000


def make_run(root, texts=("John Smith 2026-01-01",)):
    root = Path(root)
    (root / "pages_text").mkdir(parents=True, exist_ok=True)
    records = []
    for i, text in enumerate(texts):
        url = f"https://example.test/{i}"
        records.append({"url": url, "title": "Test", "fetched_at": 1_770_000_000})
        (root / "pages_text" / f"{sha1(url)}.txt").write_text(text, encoding="utf-8")
    (root / "urls_crawled.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records))
    return records


class IsolationTests(unittest.TestCase):
    def test_cpu_deadline_reaps_child(self):
        before = {p.pid for p in multiprocessing.active_children()}
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            isolated_call(busy_worker, timeout_s=0.3)
        self.assertLess(time.monotonic() - started, 4)
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_child_crash_is_failure(self):
        with self.assertRaisesRegex(RuntimeError, "without a result"):
            isolated_call(crash_worker, timeout_s=5)

    def test_large_result_does_not_deadlock(self):
        self.assertEqual(len(isolated_call(large_result, timeout_s=5)), 2_000_000)

    def test_async_cancellation_cleans_up_worker(self):
        async def scenario():
            before = {process.pid for process in multiprocessing.active_children()}
            task = asyncio.create_task(async_isolated_call(busy_worker, timeout_s=10))
            await asyncio.sleep(0.2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertEqual({process.pid for process in multiprocessing.active_children()}, before)

        asyncio.run(scenario())

    def test_live_page_extraction_runs_in_worker(self):
        from osintai.crawler import _extract_page

        title, text, links, indicators, hunt, fingerprint = isolated_call(
            _extract_page,
            Extractor(),
            "https://example.test",
            '<title>Test</title><p>threat a@example.test</p><a href="/contact">contact</a>',
            ["threat"],
            10,
            timeout_s=5,
        )
        self.assertEqual(title, "Test")
        self.assertIn("a@example.test", indicators["emails"])
        self.assertIn("https://example.test/contact", links)
        self.assertTrue(hunt["hits"])
        self.assertIsInstance(fingerprint, int)


class EnhancementTests(unittest.TestCase):
    def test_completed_file_can_be_synced_through_writable_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "validated.json"
            path.write_bytes(b"validated")
            sync_file(path)

    def test_adversarial_patterns_have_external_deadline(self):
        code = """
from osintai.extractor import Extractor
from osintai.entities import extract_extended, detect_type
for text in ['a.' * 200000 + '!', 'x-' * 200000, 'a@' + 'a.' * 200000 + '!', 'eyJaaaa-' * 50000, ' ' * 400000 + 'a@' + '.' * 400000]:
    Extractor().extract_indicators('https://example.test', text, '')
    extract_extended(text)
    detect_type(text)
assert 'a@example.test' in Extractor().extract_indicators('https://example.test', 'a@example.test', '')['emails']
"""
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=15)

    def test_unicode_hunt_offsets_and_complete_urls(self):
        text = "İ İ " + "threat https://example.test/" + "a" * 200
        result = hunt_leads(text, ["THREAT"])
        self.assertEqual(result["hits"][0]["position"], text.index("threat"))
        self.assertEqual(result["lead_urls"], [])
        self.assertEqual(
            hunt_leads("threat https://example.test/a", ["threat"])["lead_urls"], ["https://example.test/a"]
        )

    def test_attribute_and_prose_provenance(self):
        indicators = Extractor().extract_indicators(
            "https://example.test", "https://example.test/prose", '<a href="/link">label</a>'
        )
        self.assertEqual(indicators["url_provenance"]["https://example.test/link"], ["html_attribute"])
        self.assertEqual(indicators["url_provenance"]["https://example.test/prose"], ["page_prose"])

    def test_cache_is_content_addressed_and_contains_no_secrets(self):
        text = "api_key: SECRETvalue0123456789\nadmin:password123\n"
        with tempfile.TemporaryDirectory() as directory:
            cache = ExtractionCache(directory)
            key, metadata = cache.key(text, 1000, False)
            extras = extract_checkpoint(text)
            cache.put(key, metadata, extras)
            self.assertEqual(cache.get(key, metadata), extras)
            self.assertNotEqual(key, cache.key(text + "x", 1000, False)[0])
            self.assertNotEqual(key, cache.key(text, 2000, False)[0])
            self.assertNotEqual(key, cache.key(text, 1000, True)[0])
            data = (Path(directory) / f"{key}.json").read_text()
            self.assertNotIn("SECRETvalue0123456789", data)
            self.assertNotIn("password123", data)
            write_json(str(Path(directory) / f"{key}.json"), {"broken": True})
            self.assertIsNone(cache.get(key, metadata))
            self.assertEqual(cache.invalid, 1)

    def test_unicode_credential_email_is_retained(self):
        self.assertEqual(list(credentials("user@пример.com:password123")), [("user@пример.com", "password123")])

    def test_secret_redaction_extends_beyond_finding_caps(self):
        text = "\n".join(f"admin:password{i:03d}" for i in range(100)) + "\nadmin:раypal.com"
        extras = extract_checkpoint(text)
        self.assertNotIn("раypal.com", json.dumps(extras, ensure_ascii=False))
        self.assertEqual(extras["extraction_coverage"]["credential_pairs"]["omitted"], 1)

    def test_lru_cache_evicts_and_is_byte_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            records = make_run(directory, ("a" * 500, "b" * 500, "c" * 500))
            reader = RunArtifacts(directory, text_cache_bytes=1000)
            for row in records:
                self.assertEqual(len(reader.text_for(row["url"])), 500)
                self.assertLessEqual(reader.cache_bytes, 1000)
            self.assertGreater(reader.cache_evictions, 0)
            self.assertEqual(reader.text_for(records[0]["url"]), "a" * 500)

    def test_pair_budget_accounts_for_omissions(self):
        index = EntityIndex()
        for i in range(10):
            index.add("email", f"user{i}@example.test", "https://example.test")
        result = correlate(index, [], page_count=1, candidate_budget=7)
        self.assertEqual(result.stats["candidate_pairs_examined"], 7)
        self.assertEqual(result.stats["candidate_pairs_omitted"], 38)
        self.assertTrue(result.stats["partial_coverage"])

    def test_resume_reuses_cache_and_preserves_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            records = make_run(directory)
            before = {path: path.read_bytes() for path in Path(directory).rglob("*") if path.is_file()}
            first = analyze_run(directory, AnalysisOptions(use_ollama=False))
            second = analyze_run(directory, AnalysisOptions(use_ollama=False))
            self.assertEqual(first.stats["extraction_cache"]["misses"], 1)
            self.assertEqual(second.stats["extraction_cache"]["hits"], 1)
            self.assertNotEqual(first.artifacts["analysis_summary"], second.artifacts["analysis_summary"])
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)
            manifest = json.loads(Path(second.artifacts["run_manifest"]).read_text())
            self.assertIn("urls_crawled.jsonl", manifest["source_hashes"])
            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(second.stats["model_responses"]["counts"]["missing"], len(records))

    def test_failed_publication_retains_previous_pointer(self):
        with tempfile.TemporaryDirectory() as directory:
            make_run(directory)
            analyze_run(directory, AnalysisOptions(use_ollama=False))
            pointer = (Path(directory) / "analysis_latest.json").read_bytes()
            with patch("osintai.report.write_analysis_report", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    analyze_run(directory, AnalysisOptions(use_ollama=False))
            self.assertEqual((Path(directory) / "analysis_latest.json").read_bytes(), pointer)
            states = [json.loads(path.read_text())["status"] for path in Path(directory).glob("*.status.json")]
            self.assertIn("failed", states)
            self.assertEqual(len(list(Path(directory).glob("*.incomplete"))), 1)

    def test_deadline_failure_is_explicit_partial_coverage(self):
        with tempfile.TemporaryDirectory() as directory:
            make_run(directory)
            output = analyze_run(directory, AnalysisOptions(use_ollama=False, page_deadline_s=0.000001))
            self.assertEqual(output.stats["extraction_failures"][0]["status"], "timed_out")
            self.assertTrue(output.stats["partial_coverage"])
            self.assertTrue(Path(output.artifacts["analysis_report"]).is_file())

    def test_cache_write_failure_keeps_extracted_results(self):
        with tempfile.TemporaryDirectory() as directory:
            make_run(directory)
            with patch("osintai.checkpoints.ExtractionCache.put", side_effect=OSError("read only")):
                output = analyze_run(directory, AnalysisOptions(use_ollama=False))
            self.assertEqual(output.stats["pages_text_scanned"], 1)
            self.assertTrue(any("extracted results retained" in error for error in output.errors))

    def test_source_change_prevents_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            make_run(directory)
            with patch("osintai.publication.source_hashes", side_effect=[{"source": "before"}, {"source": "after"}]):
                with self.assertRaisesRegex(RuntimeError, "Source artifacts changed"):
                    analyze_run(directory, AnalysisOptions(use_ollama=False))
            self.assertFalse((Path(directory) / "analysis_latest.json").exists())

    def test_saved_model_quality_classifies_outcomes(self):
        self.assertEqual(page_status(None), "empty")
        self.assertEqual(page_status({"summary": 3}), "invalid")
        self.assertEqual(page_status({"_model_status": "timed_out"}), "timed_out")
        with tempfile.TemporaryDirectory() as directory:
            records = make_run(directory, ("a", "b", "c", "d"))
            analysis = Path(directory) / "analysis"
            analysis.mkdir()
            for row, payload in zip(records, (None, {"_model_status": "timed_out"}, [])):
                write_json(str(analysis / f"{sha1(row['url'])}.analysis.json"), payload)
            rows = RunArtifacts(directory).model_records()
            self.assertEqual([r["_model_status"] for r in rows], ["empty", "timed_out", "invalid", "missing"])

    def test_retry_overlay_rejects_external_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            run = parent / "run"
            outside = parent / "outside"
            records = make_run(run)
            (outside / "analysis").mkdir(parents=True)
            write_json(
                str(outside / "analysis" / f"{sha1(records[0]['url'])}.analysis.json"),
                {
                    "summary": "outside",
                    "key_entities": [],
                    "key_locations": [],
                    "key_dates": [],
                    "keywords": [],
                    "risk_flags": [],
                    "actionable_leads": [],
                },
            )
            write_json(
                str(outside / "run_manifest.json"),
                {"status": "completed", "source_hashes": retry_source_hashes(run)},
            )
            try:
                (run / "model_retry_escape").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            write_json(str(run / "model_retry_latest.json"), {"directory": "model_retry_escape"})
            self.assertEqual(RunArtifacts(str(run)).model_records()[0]["_model_status"], "missing")
            with self.assertRaisesRegex(RuntimeError, "escapes saved run"):
                source_hashes(run)

    def test_retry_overlay_requires_current_source_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            run = Path(directory)
            records = make_run(run)
            retry = run / "model_retry_stale"
            current_hashes = retry_source_hashes(run)
            (retry / "analysis").mkdir(parents=True)
            write_json(
                str(retry / "analysis" / f"{sha1(records[0]['url'])}.analysis.json"),
                {
                    "summary": "stale",
                    "key_entities": [],
                    "key_locations": [],
                    "key_dates": [],
                    "keywords": [],
                    "risk_flags": [],
                    "actionable_leads": [],
                },
            )
            write_json(
                str(retry / "run_manifest.json"),
                {"status": "completed", "source_hashes": current_hashes},
            )
            write_json(str(run / "model_retry_latest.json"), {"directory": retry.name})
            self.assertEqual(RunArtifacts(str(run)).model_records()[0]["_model_status"], "ok")
            (run / "pages_text" / f"{sha1(records[0]['url'])}.txt").write_text("changed", encoding="utf-8")
            self.assertEqual(RunArtifacts(str(run)).model_records()[0]["_model_status"], "missing")

    def test_model_transport_distinguishes_failures(self):
        async def scenario():
            for body, expected in (
                ({}, "missing"),
                ({"response": ""}, "empty"),
                ({"response": "{}"}, "empty"),
                ({"response": "broken"}, "invalid"),
                ({"response": '{"summary":"ok"}'}, "ok"),
            ):
                transport = httpx.MockTransport(lambda request: httpx.Response(200, json=body))
                client = httpx.AsyncClient(transport=transport)
                api = OllamaAPI()
                with patch("osintai.ollama_api.httpx.AsyncClient", return_value=client):
                    result = await api.async_generate_result("fake", "prompt")
                self.assertEqual(result["status"], expected)
                self.assertEqual(api.response_counts, {"fake": {expected: 1}})

            def timeout(request):
                raise httpx.ReadTimeout("timeout")

            client = httpx.AsyncClient(transport=httpx.MockTransport(timeout))
            api = OllamaAPI()
            with patch("osintai.ollama_api.httpx.AsyncClient", return_value=client):
                result = await api.async_generate_result("fake", "prompt")
            self.assertEqual(result["status"], "timed_out")

        asyncio.run(scenario())

    def test_model_retry_has_total_deadline(self):
        class SlowModel:
            async def async_generate_result(self, *args, **kwargs):
                await asyncio.sleep(20)

        with tempfile.TemporaryDirectory() as directory:
            make_run(directory)
            destination = asyncio.run(retry_saved(directory, SlowModel(), "slow", limit=1, timeout_s=0.01))
            manifest = json.loads((Path(destination) / "run_manifest.json").read_text())
            self.assertEqual(manifest["model_responses"]["counts"]["timed_out"], 1)

    def test_stale_extractor_version_invalidates_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = ExtractionCache(directory)
            first, _ = cache.key("some text", 1000, False)
            with patch("osintai.checkpoints.EXTRACTOR_VERSION", "new-implementation"):
                second, _ = cache.key("some text", 1000, False)
            self.assertNotEqual(first, second)

    def test_retry_is_bounded_and_keeps_originals(self):
        class FakeModel:
            calls = 0

            async def async_generate_result(self, *args, **kwargs):
                self.calls += 1
                return {"status": "empty", "payload": None}

        with tempfile.TemporaryDirectory() as directory:
            make_run(directory, ("some text", "more text", "last text"))
            model = FakeModel()
            destination = asyncio.run(retry_saved(directory, model, "fake", limit=2))
            self.assertEqual(model.calls, 2)
            manifest = json.loads((Path(destination) / "run_manifest.json").read_text())
            self.assertEqual(manifest["attempted"], 2)
            self.assertEqual(manifest["omitted"], 1)
            self.assertEqual(manifest["model_responses"]["counts"]["empty"], 2)
            self.assertFalse((Path(directory) / "analysis").exists())


if __name__ == "__main__":
    unittest.main()
