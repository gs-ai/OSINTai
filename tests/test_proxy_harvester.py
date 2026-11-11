import asyncio
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from osintai.proxyharvest.classify import (  # noqa: E402
    AsnTable,
    classify,
)
from osintai.proxyharvest.cli import build_parser, main  # noqa: E402
from osintai.proxyharvest.cycle import CycleConfig  # noqa: E402
from osintai.proxyharvest.export import export_working_set  # noqa: E402
from osintai.proxyharvest.harvest import RobotsCache, harvest_source  # noqa: E402
from osintai.proxyharvest.models import (  # noqa: E402
    ANONYMOUS,
    DATACENTER,
    ELITE,
    MOBILE_INDICATED,
    ProxyCandidate,
    RESIDENTIAL_INDICATED,
    TRANSPARENT,
    UNKNOWN_CLASS,
    ValidationResult,
    is_routable_public_ip,
)
from osintai.proxyharvest.parsers import (  # noqa: E402
    dedupe,
    parse_html,
    parse_json,
    parse_text,
)
from osintai.proxyharvest.sources import (  # noqa: E402
    RENDER_JS,
    RENDER_PYTHON,
    Source,
    SourceConfigError,
    default_sources,
    detect_kind,
    select_language,
    sources_from_config,
)
from osintai.proxyharvest.status import HarvesterState, StatusRenderer, format_duration  # noqa: E402
from osintai.proxyharvest.stealth import StealthConfig, StealthRotator  # noqa: E402
from osintai.proxyharvest.store import HarvestStore  # noqa: E402
from osintai.proxyharvest.validate import (  # noqa: E402
    ValidationConfig,
    grade_anonymity,
    parse_echo,
    proxy_url,
    validate_all,
)

LOCAL_IP = "51.15.200.9"
EXIT_IP = "45.63.10.5"


def echo_body(headers=None, origin=EXIT_IP):
    return json.dumps({"args": {}, "headers": headers or {"Host": "echo.test"}, "origin": origin})


class CandidateModelTests(unittest.TestCase):
    def test_non_routable_addresses_are_rejected(self):
        for value in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "169.254.1.1", "224.0.0.1", "0.0.0.0"):
            self.assertFalse(is_routable_public_ip(value), value)
        self.assertTrue(is_routable_public_ip("45.63.10.5"))

    def test_candidate_validity_covers_port_and_protocol(self):
        self.assertTrue(ProxyCandidate("45.63.10.5", 8080, "http").is_valid())
        self.assertFalse(ProxyCandidate("45.63.10.5", 0, "http").is_valid())
        self.assertFalse(ProxyCandidate("45.63.10.5", 8080, "gopher").is_valid())
        self.assertFalse(ProxyCandidate("10.0.0.1", 8080, "http").is_valid())


class ParserTests(unittest.TestCase):
    def test_text_parser_handles_schemes_comments_and_pipes(self):
        body = "\n".join([
            "# free list",
            "45.63.10.5:8080",
            "socks5://51.15.200.7|1080",
            "192.168.1.1:3128",
            "not-an-endpoint",
            "https://51.15.200.8:443",
        ])
        keys = [c.key for c in parse_text(body, "src")]
        self.assertEqual(
            keys,
            ["http://45.63.10.5:8080", "socks5://51.15.200.7:1080", "https://51.15.200.8:443"],
        )

    def test_text_parser_honours_source_default_protocol(self):
        keys = [c.key for c in parse_text("45.63.10.5:1080", "src", default_protocol="socks5")]
        self.assertEqual(keys, ["socks5://45.63.10.5:1080"])

    def test_json_parser_reads_nested_and_packed_shapes(self):
        body = json.dumps({
            "data": [
                {"ip": "45.63.10.5", "port": 3128, "protocols": ["socks5"]},
                {"host": "51.15.200.7:80"},
                {"ip": "10.0.0.5", "port": 8080},
            ]
        })
        self.assertEqual(
            [c.key for c in parse_json(body, "src")],
            ["socks5://45.63.10.5:3128", "http://51.15.200.7:80"],
        )

    def test_json_parser_falls_back_to_json_lines(self):
        body = '{"ip":"45.63.10.5","port":8080}\n{"ip":"51.15.200.7","port":80}\n'
        self.assertEqual(len(parse_json(body, "src")), 2)

    def test_html_parser_reads_table_rows_and_protocol_column(self):
        html = """
        <table><tr><th>IP</th><th>Port</th><th>Type</th></tr>
        <tr><td>45.63.10.5</td><td>8080</td><td>SOCKS4</td></tr>
        <tr><td>bad</td><td>x</td><td>http</td></tr></table>
        """
        self.assertEqual([c.key for c in parse_html(html, "src")], ["socks4://45.63.10.5:8080"])

    def test_html_parser_falls_back_to_text_sweep(self):
        html = "<div><p>45.63.10.5:8080</p><p>51.15.200.7:3128</p></div>"
        self.assertEqual(len(parse_html(html, "src")), 2)

    def test_dedupe_preserves_first_occurrence_order(self):
        a = ProxyCandidate("45.63.10.5", 80, "http", "one")
        b = ProxyCandidate("51.15.200.7", 80, "http", "two")
        self.assertEqual([c.source_id for c in dedupe([a, b, a])], ["one", "two"])


class LanguageDispatchTests(unittest.TestCase):
    def test_declared_renderer_wins(self):
        source = Source(id="s", url="https://x.test/a", kind="html", renderer="js")
        self.assertEqual(select_language(source, "45.63.10.5:80" * 20), RENDER_JS)

    def test_raw_kinds_never_need_a_browser(self):
        source = Source(id="s", url="https://x.test/a.txt", kind="text")
        self.assertEqual(select_language(source), RENDER_PYTHON)

    def test_static_body_with_endpoints_stays_on_python(self):
        source = Source(id="s", url="https://x.test/a", kind="auto")
        body = "<table>" + "".join(f"<tr><td>45.63.10.{i}</td><td>8080</td></tr>" for i in range(9))
        self.assertEqual(select_language(source, body), RENDER_PYTHON)

    def test_spa_shell_escalates_to_js(self):
        source = Source(id="s", url="https://x.test/a", kind="auto")
        body = '<html><body><div id="root"></div><script src="a.js"></script></body></html>'
        self.assertEqual(select_language(source, body), RENDER_JS)

    def test_detect_kind_uses_content_type_then_body(self):
        self.assertEqual(detect_kind("application/json; charset=utf-8", "{}"), "json")
        self.assertEqual(detect_kind("text/html", "<html>"), "html")
        self.assertEqual(detect_kind("text/plain", "1.2.3.4:80"), "text")
        self.assertEqual(detect_kind("", "  [1,2]"), "json")


class SourceConfigTests(unittest.TestCase):
    def test_defaults_are_all_wellformed(self):
        sources = default_sources()
        self.assertTrue(sources)
        for source in sources:
            self.assertTrue(source.url.startswith("https://"))

    def test_credentials_in_source_url_are_refused(self):
        with self.assertRaisesRegex(SourceConfigError, "without authentication"):
            Source(id="s", url="https://user:pw@x.test/list.txt")

    def test_unknown_config_keys_are_rejected(self):
        with self.assertRaisesRegex(SourceConfigError, "unknown keys"):
            sources_from_config({"sources": [{"id": "s", "url": "https://x.test/a", "spin": 1}]})

    def test_duplicate_source_ids_are_rejected(self):
        rows = [{"id": "s", "url": "https://x.test/a"}, {"id": "s", "url": "https://y.test/b"}]
        with self.assertRaisesRegex(SourceConfigError, "duplicate source id"):
            sources_from_config({"sources": rows})

    def test_empty_config_falls_back_to_defaults(self):
        self.assertEqual(len(sources_from_config({})), len(default_sources()))


class AnonymityGradingTests(unittest.TestCase):
    def test_leaked_origin_is_transparent(self):
        grade, exit_ip = grade_anonymity({"headers": {}, "origin": LOCAL_IP}, LOCAL_IP)
        self.assertEqual(grade, TRANSPARENT)
        self.assertEqual(exit_ip, LOCAL_IP)

    def test_leak_via_forwarding_header_is_transparent(self):
        echo = {"headers": {"X-Forwarded-For": LOCAL_IP}, "origin": EXIT_IP}
        self.assertEqual(grade_anonymity(echo, LOCAL_IP)[0], TRANSPARENT)

    def test_proxy_disclosure_without_leak_is_anonymous(self):
        echo = {"headers": {"Via": "1.1 squid"}, "origin": EXIT_IP}
        self.assertEqual(grade_anonymity(echo, LOCAL_IP)[0], ANONYMOUS)

    def test_clean_hop_is_elite(self):
        echo = {"headers": {"Host": "echo.test"}, "origin": EXIT_IP}
        self.assertEqual(grade_anonymity(echo, LOCAL_IP), (ELITE, EXIT_IP))

    def test_comma_joined_origin_is_a_chain_disclosure(self):
        echo = {"headers": {}, "origin": f"{EXIT_IP}, 51.15.200.44"}
        self.assertEqual(grade_anonymity(echo, LOCAL_IP), (ANONYMOUS, EXIT_IP))

    def test_parse_echo_rejects_non_echo_bodies(self):
        self.assertIsNone(parse_echo("<html>captive portal</html>"))
        self.assertIsNone(parse_echo(json.dumps({"unrelated": True})))
        self.assertIsNotNone(parse_echo(echo_body()))


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.config = ValidationConfig(
            echo_urls=("https://echo.test/get", "https://echo2.test/get"),
            concurrency=4,
            confirm=False,
            min_anonymity=ANONYMOUS,
        )

    def test_proxy_url_never_carries_credentials(self):
        self.assertEqual(proxy_url(ProxyCandidate("45.63.10.5", 8080, "http")), "http://45.63.10.5:8080")
        self.assertEqual(proxy_url(ProxyCandidate("45.63.10.5", 1080, "socks5")), "socks5://45.63.10.5:1080")

    def _run(self, handler, candidates, config=None):
        transport = httpx.MockTransport(handler)
        return asyncio.run(
            validate_all(candidates, config or self.config, LOCAL_IP, transport=transport)
        )

    def test_elite_proxy_passes(self):
        report = self._run(
            lambda request: httpx.Response(200, text=echo_body()),
            [ProxyCandidate("45.63.10.5", 8080, "http")],
        )
        self.assertEqual(len(report.passed), 1)
        self.assertEqual(report.passed[0].anonymity, ELITE)
        self.assertEqual(report.yield_rate, 1.0)

    def test_injected_body_is_rejected_as_interception(self):
        report = self._run(
            lambda request: httpx.Response(200, text="<html>ad interstitial</html>"),
            [ProxyCandidate("45.63.10.5", 8080, "http")],
        )
        self.assertEqual(len(report.passed), 0)
        self.assertIn("interception", report.failed[0].error)
        self.assertFalse(report.failed[0].body_intact)

    def test_proxy_requiring_auth_is_excluded(self):
        report = self._run(
            lambda request: httpx.Response(407),
            [ProxyCandidate("45.63.10.5", 8080, "http")],
        )
        self.assertIn("no-auth constraint", report.failed[0].error)

    def test_transparent_proxy_is_rejected_below_threshold(self):
        report = self._run(
            lambda request: httpx.Response(200, text=echo_body({"X-Forwarded-For": LOCAL_IP})),
            [ProxyCandidate("45.63.10.5", 8080, "http")],
        )
        self.assertEqual(len(report.passed), 0)
        self.assertIn("below required", report.failed[0].error)

    def test_latency_ceiling_rejects_slow_proxies(self):
        config = ValidationConfig(
            echo_urls=("https://echo.test/get",), confirm=False, max_latency_ms=0.0
        )
        report = self._run(
            lambda request: httpx.Response(200, text=echo_body()),
            [ProxyCandidate("45.63.10.5", 8080, "http")],
            config,
        )
        self.assertIn("over budget", report.failed[0].error)

    def test_confirmation_pass_drops_answer_once_proxies(self):
        state = {"calls": 0}

        def handler(request):
            state["calls"] += 1
            if state["calls"] == 1:
                return httpx.Response(200, text=echo_body())
            return httpx.Response(502)

        config = ValidationConfig(
            echo_urls=("https://echo.test/get", "https://echo2.test/get"),
            confirm=True,
            confirm_delay_s=0.0,
            min_anonymity=ANONYMOUS,
        )
        report = self._run(handler, [ProxyCandidate("45.63.10.5", 8080, "http")], config)
        self.assertEqual(len(report.passed), 0)
        self.assertIn("failed confirmation probe", report.failed[0].error)

    def test_confirmation_keeps_the_weaker_anonymity_grade(self):
        state = {"calls": 0}

        def handler(request):
            state["calls"] += 1
            if state["calls"] == 1:
                return httpx.Response(200, text=echo_body())
            return httpx.Response(200, text=echo_body({"Via": "1.1 squid"}))

        config = ValidationConfig(
            echo_urls=("https://echo.test/get", "https://echo2.test/get"),
            confirm=True,
            confirm_delay_s=0.0,
            min_anonymity=ANONYMOUS,
        )
        report = self._run(handler, [ProxyCandidate("45.63.10.5", 8080, "http")], config)
        self.assertEqual(len(report.passed), 1)
        self.assertEqual(report.passed[0].anonymity, ANONYMOUS)
        self.assertTrue(report.passed[0].confirmed)

    def test_empty_candidate_set_is_not_an_error(self):
        report = self._run(lambda request: httpx.Response(200), [])
        self.assertEqual(report.attempted, 0)
        self.assertEqual(report.yield_rate, 0.0)


class ClassificationTests(unittest.TestCase):
    def test_consumer_ptr_is_indicated_not_asserted(self):
        result = classify("45.63.10.5", ptr="c-73-1-2-3.hsd1.ca.comcast.net", resolve_ptr=False)
        self.assertEqual(result.network_class, RESIDENTIAL_INDICATED)
        self.assertLess(result.confidence, 0.7)
        self.assertTrue(any("requiring confirmation" in b for b in result.basis))

    def test_datacenter_ptr_is_classified_as_datacenter(self):
        result = classify("45.63.10.5", ptr="ec2-1-2-3-4.compute.amazonaws.com", resolve_ptr=False)
        self.assertEqual(result.network_class, DATACENTER)

    def test_mobile_ptr_is_separated_from_residential(self):
        result = classify("45.63.10.5", ptr="mobile-lte-11.carrier.test", resolve_ptr=False)
        self.assertEqual(result.network_class, MOBILE_INDICATED)

    def test_no_evidence_yields_unknown_with_stated_reasons(self):
        result = classify("45.63.10.5", ptr=None, resolve_ptr=False)
        self.assertEqual(result.network_class, UNKNOWN_CLASS)
        self.assertEqual(result.confidence, 0.0)
        self.assertTrue(any("ASN" in b for b in result.basis))

    def test_cloud_asn_overrides_consumer_looking_ptr(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "asn.csv")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("cidr,asn,org,country\n45.63.10.0/24,16509,Amazon AWS,US\n")
            table = AsnTable.load(path)
            result = classify(
                "45.63.10.5", asn_table=table,
                ptr="dsl-pool-customer.example.net", resolve_ptr=False,
            )
        self.assertEqual(result.network_class, DATACENTER)
        self.assertEqual(result.asn, 16509)
        self.assertTrue(any("overrides" in b for b in result.basis))

    def test_asn_table_prefers_the_longest_matching_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "asn.csv")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(
                    "cidr,asn,org,country\n"
                    "45.63.0.0/16,64500,Broad ISP,US\n"
                    "45.63.10.0/24,64501,Specific Net,US\n"
                )
            table = AsnTable.load(path)
            self.assertEqual(table.lookup("45.63.10.5").asn, 64501)
            self.assertEqual(table.lookup("45.63.9.5").asn, 64500)
            self.assertIsNone(table.lookup("51.15.200.1"))

    def test_isp_org_name_raises_residential_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "asn.csv")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("45.63.10.0/24,64502,Example Broadband Communications,US\n")
            table = AsnTable.load(path)
            plain = classify("45.63.10.5", ptr="dsl-1.example.net", resolve_ptr=False)
            enriched = classify(
                "45.63.10.5", asn_table=table, ptr="dsl-1.example.net", resolve_ptr=False
            )
        self.assertEqual(enriched.network_class, RESIDENTIAL_INDICATED)
        self.assertGreater(enriched.confidence, plain.confidence)


class StealthTests(unittest.TestCase):
    def test_headers_are_internally_consistent_for_chromium(self):
        rotator = StealthRotator(StealthConfig(user_agents=["Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36"]))
        headers = rotator.headers()
        self.assertIn("Sec-Fetch-Mode", headers)
        firefox = StealthRotator(StealthConfig(user_agents=["Mozilla/5.0 Firefox/126.0"]))
        self.assertNotIn("Sec-Fetch-Mode", firefox.headers())

    def test_tls_context_never_weakens_verification(self):
        import ssl

        context = StealthRotator(StealthConfig(randomize_tls_order=True)).build_ssl_context()
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_chaining_is_off_unless_explicitly_enabled(self):
        rotator = StealthRotator(StealthConfig())
        rotator.set_working_pool([
            {"ip": "45.63.10.5", "port": 8080, "protocol": "http",
             "anonymity": ELITE, "last_ok_epoch": 9e12}
        ])
        self.assertIsNone(rotator.chained_proxy())

    def test_chaining_rejects_stale_and_low_grade_entries(self):
        config = StealthConfig(allow_chaining=True, chain_min_anonymity=ELITE, chain_max_age_s=60)
        rotator = StealthRotator(config)
        rotator.set_working_pool([
            {"ip": "45.63.10.5", "port": 8080, "protocol": "http",
             "anonymity": ANONYMOUS, "last_ok_epoch": 9e12},
            {"ip": "51.15.200.7", "port": 8080, "protocol": "http",
             "anonymity": ELITE, "last_ok_epoch": 0},
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(rotator.chained_proxy())

    def test_chaining_uses_a_fresh_elite_entry_when_enabled(self):
        import time

        config = StealthConfig(allow_chaining=True, chain_min_anonymity=ELITE)
        rotator = StealthRotator(config)
        rotator.set_working_pool([
            {"ip": "45.63.10.5", "port": 8080, "protocol": "http",
             "anonymity": ELITE, "last_ok_epoch": time.time()}
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rotator.chained_proxy(), "http://45.63.10.5:8080")

    def test_delay_stays_within_configured_bounds(self):
        rotator = StealthRotator(StealthConfig(min_delay_s=1.0, max_delay_s=2.0))
        for _ in range(50):
            self.assertTrue(1.0 <= rotator.delay_s() <= 2.0)


class HarvestTests(unittest.TestCase):
    def _harvest(self, handler, source, allow_js=False, robots=None):
        async def run():
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(transport=transport) as client:
                return await harvest_source(
                    client, source, StealthRotator(StealthConfig()), robots, allow_js
                )

        return asyncio.run(run())

    def test_text_source_is_fetched_and_parsed(self):
        source = Source(id="s", url="https://x.test/list.txt", kind="text", renderer="python")
        result = self._harvest(
            lambda request: httpx.Response(200, text="45.63.10.5:8080\n51.15.200.7:3128\n",
                                           headers={"content-type": "text/plain"}),
            source,
        )
        self.assertTrue(result.ok)
        self.assertEqual(len(result.candidates), 2)

    def test_non_200_source_is_reported_not_raised(self):
        source = Source(id="s", url="https://x.test/list.txt", kind="text", renderer="python")
        result = self._harvest(lambda request: httpx.Response(503), source)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "http 503")

    def test_js_source_is_skipped_without_the_flag(self):
        source = Source(id="s", url="https://x.test/app", kind="html", renderer="js")
        result = self._harvest(lambda request: httpx.Response(200, text="x"), source)
        self.assertFalse(result.ok)
        self.assertIn("--enable-js", result.skipped_reason)

    def test_robots_disallow_skips_the_source(self):
        def handler(request):
            if request.url.path == "/robots.txt":
                return httpx.Response(200, text="User-agent: *\nDisallow: /list\n")
            return httpx.Response(200, text="45.63.10.5:8080")

        source = Source(id="s", url="https://x.test/list.txt", kind="text", renderer="python")
        result = self._harvest(handler, source, robots=RobotsCache())
        self.assertFalse(result.ok)
        self.assertEqual(result.skipped_reason, "disallowed by robots.txt")

    def test_missing_robots_fails_open(self):
        def handler(request):
            if request.url.path == "/robots.txt":
                return httpx.Response(404)
            return httpx.Response(200, text="45.63.10.5:8080",
                                  headers={"content-type": "text/plain"})

        source = Source(id="s", url="https://x.test/list.txt", kind="text", renderer="python")
        result = self._harvest(handler, source, robots=RobotsCache())
        self.assertTrue(result.ok)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = HarvestStore(os.path.join(self.directory.name, "harvest.sqlite"))

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def _passing(self, ip="45.63.10.5", port=8080):
        candidate = ProxyCandidate(ip, port, "http", "src")
        return ValidationResult(
            candidate=candidate, ok=True, latency_ms=250.0,
            anonymity=ELITE, exit_ip=ip, confirmed=True,
        )

    def test_working_set_roundtrip_preserves_classification_basis(self):
        result = self._passing()
        classification = classify("45.63.10.5", ptr="dsl-1.example.net", resolve_ptr=False)
        self.store.upsert_working(result, classification)
        rows = self.store.working_set()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["network_class"], RESIDENTIAL_INDICATED)
        self.assertIn("PTR consumer-access tokens", rows[0]["classification_basis"])

    def test_repeat_success_increments_rather_than_duplicating(self):
        classification = classify("45.63.10.5", ptr=None, resolve_ptr=False)
        self.store.upsert_working(self._passing(), classification)
        self.store.upsert_working(self._passing(), classification)
        rows = self.store.working_set()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ok_count"], 2)

    def test_retirement_removes_a_proxy_from_the_working_set(self):
        classification = classify("45.63.10.5", ptr=None, resolve_ptr=False)
        self.store.upsert_working(self._passing(), classification)
        key = "http://45.63.10.5:8080"
        self.store.mark_failures([key], retire_after=2)
        self.assertEqual(self.store.working_size(), 1)
        self.store.mark_failures([key], retire_after=2)
        self.assertEqual(self.store.working_size(), 0)
        self.assertEqual(self.store.stats()["working_retired"], 1)

    def test_returning_proxy_is_unretired(self):
        classification = classify("45.63.10.5", ptr=None, resolve_ptr=False)
        self.store.upsert_working(self._passing(), classification)
        key = "http://45.63.10.5:8080"
        self.store.mark_failures([key], retire_after=1)
        self.assertEqual(self.store.working_size(), 0)
        self.store.upsert_working(self._passing(), classification)
        self.assertEqual(self.store.working_size(), 1)

    def test_candidates_record_repeat_sightings(self):
        candidate = ProxyCandidate("45.63.10.5", 8080, "http", "src")
        self.store.record_candidates([candidate])
        self.store.record_candidates([candidate])
        self.assertEqual(self.store.stats()["candidates_total"], 1)

    def test_cycle_lifecycle_records_metrics(self):
        cycle_id = self.store.start_cycle(1200.0)
        self.store.finish_cycle(cycle_id, candidates=10, validated=10, passed=2, yield_rate=0.2)
        cycles = self.store.recent_cycles()
        self.assertEqual(cycles[0]["passed"], 2)
        self.assertIsNotNone(cycles[0]["finished_at"])

    def test_working_set_is_ordered_by_latency(self):
        classification = classify("45.63.10.5", ptr=None, resolve_ptr=False)
        slow = self._passing("45.63.10.5", 8080)
        slow.latency_ms = 900.0
        fast = self._passing("51.15.200.7", 8080)
        fast.latency_ms = 120.0
        self.store.upsert_working(slow, classification)
        self.store.upsert_working(fast, classification)
        self.assertEqual(self.store.working_set()[0]["ip"], "51.15.200.7")


class ExportTests(unittest.TestCase):
    def _rows(self):
        return [{
            "key": "http://45.63.10.5:8080", "ip": "45.63.10.5", "port": 8080,
            "protocol": "http", "source_id": "src", "latency_ms": 250.0,
            "anonymity": ELITE, "exit_ip": "45.63.10.5",
            "network_class": RESIDENTIAL_INDICATED, "classification_confidence": 0.35,
            "classification_basis": "PTR consumer-access tokens: dsl",
            "asn": None, "as_org": None, "country": None, "ptr": "dsl-1.example.net",
            "first_seen": "2026-01-01T00:00:00Z", "last_ok": "2026-01-01T00:00:00Z",
            "last_ok_epoch": 1767225600.0, "ok_count": 1, "fail_count": 0,
        }]

    def test_all_formats_are_written_with_stable_latest_copies(self):
        with tempfile.TemporaryDirectory() as directory:
            result = export_working_set(
                directory, self._rows(), formats=["csv", "json", "jsonl", "txt"]
            )
            self.assertEqual(result.count, 1)
            for name in ("working_set_latest.csv", "working_set_latest.json",
                         "working_set_latest.jsonl", "working_set_latest.txt"):
                self.assertTrue(os.path.isfile(os.path.join(directory, name)), name)

            with open(os.path.join(directory, "working_set_latest.txt"), encoding="utf-8") as handle:
                self.assertEqual(handle.read().strip(), "http://45.63.10.5:8080")

    def test_manifest_carries_the_classification_notice(self):
        with tempfile.TemporaryDirectory() as directory:
            export_working_set(directory, self._rows(), formats=["json"])
            with open(os.path.join(directory, "working_set_latest.json"), encoding="utf-8") as handle:
                payload = json.load(handle)
        notice = payload["manifest"]["classification_notice"]
        self.assertIn("not verified subscriber-line records", notice)
        self.assertEqual(payload["manifest"]["by_network_class"], {RESIDENTIAL_INDICATED: 1})

    def test_internal_epoch_field_is_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            export_working_set(directory, self._rows(), formats=["jsonl"])
            with open(os.path.join(directory, "working_set_latest.jsonl"), encoding="utf-8") as handle:
                row = json.loads(handle.readline())
        self.assertNotIn("last_ok_epoch", row)

    def test_empty_working_set_still_produces_readable_files(self):
        with tempfile.TemporaryDirectory() as directory:
            result = export_working_set(directory, [], formats=["csv", "txt"])
            self.assertEqual(result.count, 0)
            with open(os.path.join(directory, "working_set_latest.csv"), encoding="utf-8") as handle:
                self.assertTrue(handle.readline().startswith("key,ip,port"))


class CycleConfigTests(unittest.TestCase):
    def test_interval_bounds_are_normalised(self):
        config = CycleConfig(interval_min_s=600, interval_max_s=300)
        self.assertEqual(config.interval_max_s, 600)

    def test_export_cadence_cannot_be_zero(self):
        self.assertEqual(CycleConfig(export_every_cycles=0).export_every_cycles, 1)

    def test_sampled_interval_stays_in_range(self):
        from osintai.proxyharvest.cycle import ProxyHarvester

        with tempfile.TemporaryDirectory() as directory:
            store = HarvestStore(os.path.join(directory, "h.sqlite"))
            try:
                harvester = ProxyHarvester(
                    sources=[], store=store,
                    cycle_config=CycleConfig(interval_min_s=19 * 60, interval_max_s=23 * 60),
                    renderer=StatusRenderer(quiet=True),
                )
                for _ in range(100):
                    self.assertTrue(19 * 60 <= harvester.sample_interval() <= 23 * 60)
            finally:
                store.close()


class StatusTests(unittest.TestCase):
    def test_duration_formatting(self):
        self.assertEqual(format_duration(0), "00m00s")
        self.assertEqual(format_duration(75), "01m15s")
        self.assertEqual(format_duration(3725), "1h02m05s")
        self.assertEqual(format_duration(-5), "00m00s")

    def test_remaining_never_goes_negative(self):
        state = HarvesterState(interval_s=10.0, cycle_started_at=0.0)
        self.assertEqual(state.remaining_s, 0.0)

    def test_json_status_emits_one_object_per_render(self):
        stream = io.StringIO()
        renderer = StatusRenderer(json_mode=True, stream=stream)
        renderer.render(HarvesterState(phase="validate", working_size=7))
        payload = json.loads(stream.getvalue().strip())
        self.assertEqual(payload["phase"], "validate")
        self.assertEqual(payload["working_size"], 7)


class CliTests(unittest.TestCase):
    def test_interval_bounds_are_validated(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--interval-min", "25", "--interval-max", "5"])

    def test_yield_abort_must_be_a_fraction(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--yield-abort", "42"])

    def test_list_sources_emits_parseable_json(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["--list-sources"])
        self.assertEqual(code, 0)
        rows = json.loads(buffer.getvalue())
        self.assertTrue(all("url" in row for row in rows))

    def test_parser_defaults_match_the_specified_cycle_window(self):
        args = build_parser().parse_args([])
        self.assertEqual((args.interval_min, args.interval_max), (19.0, 23.0))


if __name__ == "__main__":
    unittest.main()
