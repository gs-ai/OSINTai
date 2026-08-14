"""Regression and capability tests for the OSINTai analysis layer."""

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from osintai import correlation, entities, evaluation, hypotheses, patterns  # noqa: E402
from osintai import multimodel, pivots, prompts, temporal  # noqa: E402
from osintai.analyzer import compute_page_signal  # noqa: E402
from osintai.pipeline import AnalysisOptions, analyze_run  # noqa: E402
from osintai.provenance import (  # noqa: E402
    DERIVED,
    HIGH,
    HYPOTHESIS,
    MODEL,
    OBSERVED,
    CheckResult,
    Confidence,
    Finding,
    Hypothesis,
    cross_model_confidence,
    sort_findings,
    source_support,
)
from osintai.report import write_analysis_report, write_report  # noqa: E402
from osintai.storage import append_jsonl, safe_mkdir, sha1  # noqa: E402


def _read(path: str) -> str:
    """Read a whole file and close it. Keeps the suite free of ResourceWarnings."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# Regression: existing behavior
# ---------------------------------------------------------------------------

BASELINE_PROMPT = """
You are an OSINT analyst. Produce a structured intelligence extraction from this webpage.

Rules:
- No filler. No moralizing.
- Only use evidence from the content.
- Output valid JSON only.

Return schema:
{
  "url": "...",
  "title": "...",
  "summary": "2-4 sentences",
  "key_entities": ["..."],
  "key_locations": ["..."],
  "key_dates": ["..."],
  "keywords": ["..."],
  "risk_flags": ["..."],
  "actionable_leads": ["..."]
}

URL: https://one.test/page
TITLE: Example Title

CONTENT:
Body text.
""".strip()


class PromptRegressionTests(unittest.TestCase):
    def test_standard_prompt_is_byte_identical_to_baseline(self):
        # osint-tuned-v3 was trained against this exact text. If this fails, the model is
        # being sent something it was not tuned for.
        self.assertEqual(
            prompts.page_prompt("https://one.test/page", "Example Title", "Body text."),
            BASELINE_PROMPT,
        )

    def test_crawler_prompt_delegates_without_changing_output(self):
        from osintai.crawler import AsyncCrawler

        crawler = object.__new__(AsyncCrawler)
        crawler.prompt_profile = prompts.STANDARD
        self.assertEqual(
            crawler._analysis_prompt("https://one.test/page", "Example Title", "Body text."),
            BASELINE_PROMPT,
        )

    def test_threat_profile_is_a_different_prompt_with_the_same_schema(self):
        threat = prompts.page_prompt("https://one.test/", "T", "Body", profile=prompts.THREAT)
        self.assertNotEqual(threat, BASELINE_PROMPT)
        for key in ("key_entities", "risk_flags", "actionable_leads", "summary"):
            self.assertIn(key, threat)


class ScoringRegressionTests(unittest.TestCase):
    def test_page_signal_formula_is_unchanged(self):
        indicators = {
            "emails": ["a@b.test"] * 12,      # capped at 10 -> 20.0
            "phones": ["8165550142"] * 7,     # capped at 5  -> 7.5
            "btc_addresses": ["x"] * 4,       # capped at 3  -> 9.0
            "eth_addresses": ["y"] * 4,       # capped at 3  -> 9.0
            "social_handles": ["@z"] * 8,     # capped at 5  -> 5.0
        }
        analysis = {
            "risk_flags": ["a", "b"],                    # 10.0
            "actionable_leads": ["l1", "l2", "l3"],      # 9.0
            "key_entities": ["e"] * 15,                  # capped at 10 -> 10.0
            "key_locations": ["loc"] * 9,                # capped at 5  -> 7.5
            "keywords": ["k"] * 30,                      # capped at 20 -> 10.0
        }
        self.assertEqual(compute_page_signal(indicators, analysis), 97.0)

    def test_page_signal_tolerates_empty_analysis(self):
        self.assertEqual(compute_page_signal({}, {}), 0.0)


class ReportRegressionTests(unittest.TestCase):
    def test_ranked_report_format_is_unchanged(self):
        with tempfile.TemporaryDirectory() as run_dir:
            path = write_report(run_dir, [
                {"url": "https://one.test/", "score": 12.5, "title": "T",
                 "summary": "S", "risk_flags": ["rf"]},
            ])
            content = _read(path)
            self.assertTrue(content.startswith("OSINTai Report\n" + "=" * 60))
            self.assertIn("01. score=12.5  https://one.test/", content)
            self.assertIn("    title: T", content)
            self.assertIn("    summary: S", content)
            self.assertIn("    risk_flags: rf", content)
            self.assertTrue(os.path.exists(os.path.join(run_dir, "ranked_pages.json")))


class ExtractorRegressionTests(unittest.TestCase):
    def test_indicator_schema_keys_are_unchanged(self):
        from osintai.extractor import Extractor

        expected = {
            "url", "domain", "domains", "emails", "phones", "urls", "ip_addresses",
            "btc_addresses", "eth_addresses", "social_handles", "email_count",
            "phone_count", "url_count", "domain_count", "ip_count", "btc_count",
            "eth_count", "social_count",
        }
        indicators = Extractor().extract_indicators("https://one.test/", "text", "<html></html>")
        self.assertEqual(set(indicators), expected)


class NoTrainingInOSINTaiTests(unittest.TestCase):
    def test_no_training_dependency_or_entry_point_exists(self):
        # Training must never run during OSINT analysis, and the heavyweight training
        # stack must never become an OSINTai dependency.
        src = os.path.join(os.path.dirname(__file__), "..", "src", "osintai")
        forbidden = ("import mlx", "from mlx", "import torch", "lora_rank", "safetensors")
        for name in os.listdir(src):
            if not name.endswith(".py"):
                continue
            body = _read(os.path.join(src, name))
            for token in forbidden:
                self.assertNotIn(token, body, f"{name} references training stack: {token}")

        requirements = _read(
            os.path.join(os.path.dirname(__file__), "..", "requirements.txt")
        ).lower()
        for package in ("mlx", "torch", "transformers", "peft", "numpy"):
            self.assertNotIn(package, requirements)


# ---------------------------------------------------------------------------
# Capability: provenance
# ---------------------------------------------------------------------------

class ProvenanceTests(unittest.TestCase):
    def test_finding_rejects_unknown_origin_and_priority(self):
        with self.assertRaises(ValueError):
            Finding(check="c", item="i", reason="r", next_step="n", origin="FACT")
        with self.assertRaises(ValueError):
            Finding(check="c", item="i", reason="r", next_step="n", priority="URGENT")

    def test_hypothesis_origin_cannot_be_relabelled_as_observed(self):
        hypothesis = Hypothesis(statement="maybe")
        hypothesis.origin = OBSERVED  # even if reassigned...
        payload = hypothesis.to_dict()
        self.assertEqual(payload["origin"], HYPOTHESIS)  # ...serialization stays honest
        self.assertEqual(payload["label"], HYPOTHESIS)

    def test_confidence_kinds_stay_distinct_and_clamped(self):
        with self.assertRaises(ValueError):
            Confidence("vibes", 0.5)
        self.assertEqual(Confidence("deterministic", 5.0).value, 1.0)
        self.assertEqual(Confidence("deterministic", -3.0).value, 0.0)

    def test_source_support_scales_with_independent_sources(self):
        self.assertEqual(source_support([]).value, 0.0)
        one = source_support(["https://a.test/"]).value
        three = source_support(["https://a.test/", "https://b.test/", "https://c.test/"]).value
        self.assertLess(one, three)
        self.assertLess(three, 1.0)  # crawled corroboration never reaches certainty

    def test_findings_sort_high_priority_first(self):
        low = Finding(check="b", item="1", reason="", next_step="", priority="LOW")
        high = Finding(check="a", item="2", reason="", next_step="", priority=HIGH)
        self.assertEqual([f.priority for f in sort_findings([low, high])], [HIGH, "LOW"])


# ---------------------------------------------------------------------------
# Capability: entities
# ---------------------------------------------------------------------------

class EntityTests(unittest.TestCase):
    def test_identifier_typing(self):
        self.assertEqual(entities.detect_type("j.doe@example.test"), entities.EMAIL)
        self.assertEqual(entities.detect_type("(816) 555-0142"), entities.PHONE)
        self.assertEqual(entities.detect_type("John Martinez"), entities.NAME)
        self.assertEqual(entities.detect_type("h4ckerman"), entities.USERNAME)

    def test_one_number_written_four_ways_is_one_entity(self):
        index = entities.EntityIndex()
        for written in ("816-555-0142", "(816) 555-0142", "+18165550142", "816.555.0142"):
            index.add(entities.PHONE, written, f"https://{written}.test/")
        self.assertEqual(len(index.of_kind(entities.PHONE)), 1)
        entity = index.of_kind(entities.PHONE)[0]
        self.assertEqual(entity.canonical_value, "8165550142")
        self.assertEqual(len(entity.sources), 4)
        self.assertEqual(len(entity.observed_forms), 4)

    def test_observed_forms_are_separate_from_possible_variants(self):
        index = entities.EntityIndex()
        index.add(entities.PHONE, "816-555-0142", "https://a.test/")
        entity = index.of_kind(entities.PHONE)[0]
        self.assertEqual(entity.observed_forms, ["816-555-0142"])
        self.assertGreater(len(entity.variants), 1)  # possible forms, not seen ones

    def test_extended_extraction_finds_new_indicator_classes(self):
        extras = entities.extract_extended(
            "Meeting on 2024-01-31 with John Martinez at 4421 Troost Ave.\n"
            "api_key: AKIAIOSFODNN7EXAMPLEKEY123\n"
        )
        self.assertIn("2024-01-31", extras["dates"])
        self.assertIn("John Martinez", extras["name_candidates"])
        self.assertTrue(any("4421 Troost Ave" in a for a in extras["addresses"]))
        self.assertTrue(extras["api_tokens"])

    def test_non_ascii_domains_and_handles_are_recovered(self):
        # The crawler's own patterns are ASCII-only, so a Cyrillic lookalike never reaches
        # the homoglyph check unless this recovers it.
        extras = entities.extract_extended(
            "Partner pаypal.test and handle @аdmin alongside example.test and @admin"
        )
        self.assertIn("pаypal.test", extras["unicode_domains"])
        self.assertIn("@аdmin", extras["unicode_handles"])
        # Plain ASCII values are already in the crawler's output and are not duplicated.
        self.assertNotIn("example.test", extras["unicode_domains"])
        self.assertNotIn("@admin", extras["unicode_handles"])

    def test_bare_urls_are_not_read_as_credentials(self):
        extras = entities.extract_extended(
            "https://example.test/some/path\nhttp://other.test/thing\nNote: something long here\n"
        )
        self.assertEqual(extras["credential_pairs"], [])

    def test_real_credential_shape_is_still_caught(self):
        extras = entities.extract_extended("admin:hunter2secret\n")
        self.assertEqual(len(extras["credential_pairs"]), 1)

    def test_multi_source_ranking(self):
        index = entities.EntityIndex()
        index.add(entities.EMAIL, "a@x.test", "https://1.test/")
        for i in range(4):
            index.add(entities.EMAIL, "b@x.test", f"https://{i}.test/")
        top = index.multi_source(minimum=2)
        self.assertEqual(top[0].canonical_value, "b@x.test")


# ---------------------------------------------------------------------------
# Capability: deterministic checks
# ---------------------------------------------------------------------------

class PatternTests(unittest.TestCase):
    def _index_with(self, kind, value):
        index = entities.EntityIndex()
        index.add(kind, value, "https://source.test/")
        return index

    def test_cyrillic_homoglyph_domain_is_flagged_with_ascii_form(self):
        index = self._index_with(entities.DOMAIN, "pаypal.test")  # Cyrillic a
        result = patterns.check_homoglyphs(index)
        self.assertEqual(result.finding_count, 1)
        finding = result.findings[0]
        self.assertEqual(finding.origin, DERIVED)
        self.assertEqual(finding.evidence["ascii_normalization"], "paypal.test")

    def test_zero_width_character_is_high_priority(self):
        index = self._index_with(entities.USERNAME, "ad​min")
        result = patterns.check_homoglyphs(index)
        self.assertEqual(result.findings[0].priority, HIGH)

    def test_plain_ascii_produces_no_homoglyph_findings(self):
        index = self._index_with(entities.DOMAIN, "example.test")
        self.assertEqual(patterns.check_homoglyphs(index).finding_count, 0)

    def test_private_and_public_ip_classification(self):
        for private in ("10.0.0.1", "192.168.1.1", "172.16.5.4", "127.0.0.1"):
            self.assertTrue(patterns._is_private_ip(private), private)
        for public in ("8.8.8.8", "172.32.0.1", "1.1.1.1"):
            self.assertFalse(patterns._is_private_ip(public), public)

    def test_sensitive_and_internal_indicators_are_flagged(self):
        index = entities.EntityIndex()
        index.add(entities.EMAIL, "agent@agency.gov", "https://a.test/")
        index.add(entities.DOMAIN, "base.mil", "https://a.test/")
        index.add(entities.IP, "10.1.2.3", "https://a.test/")
        checks = {f.check for f in patterns.check_sensitive_infrastructure(index).findings}
        self.assertEqual(
            checks, {"Sensitive Email Domain", "Sensitive Domain", "Internal IP Exposure"}
        )

    def test_secret_findings_never_record_the_secret_value(self):
        extras = {"https://a.test/": entities.extract_extended(
            "api_key: SUPERSECRETVALUE0123456789\nadmin:hunter2secret\n"
        )}
        result = patterns.check_secret_exposure(extras)
        self.assertGreater(result.finding_count, 0)
        serialized = json.dumps([f.to_dict() for f in result.findings])
        self.assertNotIn("SUPERSECRETVALUE0123456789", serialized)
        self.assertNotIn("hunter2secret", serialized)
        self.assertIn("value_recorded", serialized)

    def test_jwt_payload_is_decoded(self):
        # {"iss":"acme","sub":"1234"}
        # Assemble the fixture so scanners do not mistake test data for a live token.
        token = ".".join(
            ("eyJ" + "hbGciOiJIUzI1NiJ9", "eyJ" + "pc3MiOiJhY21lIiwic3ViIjoiMTIzNCJ9", "abcdefghij")
        )
        claims = patterns.decode_jwt_payload(token)
        self.assertEqual(claims["iss"], "acme")
        result = patterns.check_secret_exposure({"https://a.test/": {
            "api_tokens": [], "jwts": [token], "credential_pairs": [],
        }})
        jwt_finding = next(f for f in result.findings if f.check == "JWT Present")
        self.assertIn("iss", jwt_finding.evidence["claim_keys"])
        self.assertNotIn(token, json.dumps(jwt_finding.to_dict()))

    def test_malformed_jwt_returns_none(self):
        self.assertIsNone(patterns.decode_jwt_payload("not.a.jwt"))
        self.assertIsNone(patterns.decode_jwt_payload("onlyonepart"))

    def test_generated_content_fingerprint(self):
        pages = [{"url": "https://a.test/"}, {"url": "https://b.test/"}]
        texts = {
            "https://a.test/": "As an AI language model, I cannot provide that information.",
            "https://b.test/": "An ordinary article about municipal drainage.",
        }
        result = patterns.check_generated_text(pages, lambda u: texts.get(u, ""))
        self.assertEqual(result.finding_count, 1)
        self.assertEqual(result.findings[0].item, "https://a.test/")

    def test_outlier_detection_requires_enough_pages(self):
        index = entities.EntityIndex()
        result = patterns.check_recurring_and_outliers(index, [{"url": "a", "score": 1}])
        self.assertTrue(any("Fewer than 5" in n for n in result.notes))


# ---------------------------------------------------------------------------
# Capability: correlation
# ---------------------------------------------------------------------------

class CorrelationTests(unittest.TestCase):
    def test_co_occurring_identifiers_link_with_evidence(self):
        index = entities.EntityIndex()
        for page in ("https://p1.test/", "https://p2.test/"):
            index.add(entities.EMAIL, "target@x.test", page)
            index.add(entities.USERNAME, "@targethandle", page)
        result = correlation.correlate(index, [], page_count=2)
        self.assertGreater(len(result.rows), 0)
        row = result.rows[0]
        self.assertEqual(row["status"], "CANDIDATE")
        self.assertGreater(row["evidence_count"], 0)

    def test_identifiers_that_never_co_occur_are_not_linked(self):
        index = entities.EntityIndex()
        index.add(entities.EMAIL, "a@x.test", "https://p1.test/")
        index.add(entities.USERNAME, "@unrelated", "https://p2.test/")
        rows = correlation.correlate(index, [], page_count=2).rows
        self.assertFalse([r for r in rows if r["relation"] == correlation.CO_OCCURS])

    def test_index_position_does_not_create_links(self):
        # Same-index values from different pages must not produce a relationship.
        index = entities.EntityIndex()
        index.add(entities.EMAIL, "first@x.test", "https://p1.test/")
        index.add(entities.PHONE, "8165550142", "https://p2.test/")
        index.add(entities.EMAIL, "second@x.test", "https://p3.test/")
        index.add(entities.PHONE, "8165550143", "https://p4.test/")
        rows = correlation.correlate(index, [], page_count=4).rows
        self.assertEqual([r for r in rows if r["relation"] == correlation.CO_OCCURS], [])

    def test_site_wide_identifiers_are_excluded_from_pairing(self):
        index = entities.EntityIndex()
        pages = [f"https://p{i}.test/" for i in range(20)]
        for page in pages:
            index.add(entities.EMAIL, "footer@site.test", page)   # on every page
            index.add(entities.USERNAME, "@sitehandle", page)     # on every page
        index.add(entities.EMAIL, "rare@site.test", pages[0])
        rows = correlation.correlate(index, [], page_count=20).rows
        pairs = [r for r in rows if r["relation"] == correlation.CO_OCCURS]
        for row in pairs:
            self.assertNotIn("footer@site.test", (row["left"]["value"], row["right"]["value"]))

    def test_email_local_part_matching_a_handle_is_a_candidate_not_an_identity(self):
        index = entities.EntityIndex()
        index.add(entities.EMAIL, "jmartinez@x.test", "https://p.test/")
        index.add(entities.USERNAME, "@jmartinez", "https://p.test/")
        rows = correlation.correlate(index, [], page_count=1).rows
        match = next(r for r in rows if r["relation"] == correlation.LOCAL_PART_MATCH)
        self.assertEqual(match["status"], "CANDIDATE")
        self.assertLess(match["score"], 0.8)
        self.assertIn("pivot, not an identity", match["rationale"])

    def test_domain_families_group_subdomains(self):
        index = entities.EntityIndex()
        for host in ("mail.example.test", "vpn.example.test", "www.example.test"):
            index.add(entities.DOMAIN, host, "https://p.test/")
        rows = correlation.correlate(index, [], page_count=1).rows
        self.assertTrue([r for r in rows if r["relation"] == correlation.SHARES_DOMAIN])

    def test_domain_url_mapping_ranks_by_frequency(self):
        rows = [
            {"url": "https://a.test/1", "domain": "a.test",
             "urls": ["https://b.test/x", "https://b.test/y", "https://c.test/z"]},
        ]
        mapping = correlation.map_domains_to_urls(rows)
        self.assertEqual(mapping["top_domains"][0][0], "b.test")


# ---------------------------------------------------------------------------
# Capability: temporal
# ---------------------------------------------------------------------------

class TemporalTests(unittest.TestCase):
    def test_parses_iso_and_written_date_forms(self):
        for value in ("2024-01-31", "2024-01-31T14:22:00Z", "01/31/2024",
                      "Feb 28, 2026", "28 February 2026", "March 2025"):
            self.assertIsNotNone(temporal.parse_timestamp(value), value)
        self.assertIsNone(temporal.parse_timestamp("sometime last spring"))

    def test_events_are_ordered_and_keep_their_raw_form(self):
        records = [
            {"url": "https://b.test/", "fetched_at": 1_700_000_100, "title": "B"},
            {"url": "https://a.test/", "fetched_at": 1_700_000_000, "title": "A"},
        ]
        events, errors = temporal.build_events(records, {"https://a.test/": ["2020-05-05"]})
        self.assertEqual(errors, [])
        self.assertEqual([e.when for e in events], sorted(e.when for e in events))
        content = next(e for e in events if e.kind == temporal.CONTENT_DATE)
        self.assertEqual(content.raw, "2020-05-05")
        self.assertEqual(content.source, "https://a.test/")

    def test_gap_over_threshold_is_flagged_and_under_is_not(self):
        records = [{"url": "https://a.test/", "fetched_at": time.time(), "title": "A"}]
        dates = {"https://a.test/": ["2020-01-01", "2020-01-20", "2021-06-01"]}
        events, _ = temporal.build_events(records, dates)
        result = temporal.analyze_timeline(events, gap_threshold_days=90)
        gaps = [f for f in result.findings if f.check == "Activity Gap"]
        self.assertEqual(len(gaps), 1)
        self.assertGreater(gaps[0].evidence["gap_days"], 90)

    def test_unparseable_dates_become_errors_not_exceptions(self):
        records = [{"url": "https://a.test/", "fetched_at": time.time()}]
        events, errors = temporal.build_events(records, {"https://a.test/": ["not a date"]})
        self.assertEqual(len(errors), 1)
        self.assertTrue(events)

    def test_empty_event_stream_is_handled(self):
        result = temporal.analyze_timeline([], gap_threshold_days=90)
        self.assertEqual(result.finding_count, 0)
        self.assertTrue(result.notes)


# ---------------------------------------------------------------------------
# Capability: hypotheses and leads
# ---------------------------------------------------------------------------

class HypothesisAndLeadTests(unittest.TestCase):
    def test_hypotheses_carry_confirmation_and_refutation_conditions(self):
        finding = Finding(
            check="Unicode / Homoglyph", item="pаypal.test",
            reason="non-ASCII", next_step="compare",
            evidence={"ascii_normalization": "paypal.test"},
            sources=["https://a.test/"],
        )
        derived = hypotheses.from_findings([finding])
        self.assertEqual(len(derived), 1)
        self.assertTrue(derived[0].would_confirm)
        self.assertTrue(derived[0].would_refute)
        self.assertEqual(derived[0].to_dict()["origin"], HYPOTHESIS)

    def test_model_hypotheses_are_labelled_with_their_model(self):
        payload = {"hypotheses": [
            {"statement": "The sites share an operator.", "confidence": 0.8},
        ]}
        results = hypotheses.from_model(payload, "test-model:latest", ["https://a.test/"])
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].model, "test-model:latest")
        self.assertEqual(results[0].to_dict()["label"], HYPOTHESIS)
        self.assertEqual(results[0].confidence[0].kind, "model_self")

    def test_model_hypotheses_from_garbage_payload(self):
        self.assertEqual(hypotheses.from_model({"nope": 1}, "m", []), [])
        self.assertEqual(hypotheses.from_model({"hypotheses": "text"}, "m", []), [])

    def test_leads_are_generated_per_identifier_type_with_risk_notes(self):
        index = entities.EntityIndex()
        index.add(entities.EMAIL, "j@x.test", "https://p.test/")
        index.add(entities.USERNAME, "@jhandle", "https://p.test/")
        index.add(entities.PHONE, "8165550142", "https://p.test/")
        index.add(entities.DOMAIN, "x.test", "https://p.test/")
        leads = pivots.generate_leads(index)
        kinds = {lead.seed_type for lead in leads}
        self.assertEqual(
            kinds, {entities.EMAIL, entities.USERNAME, entities.PHONE, entities.DOMAIN}
        )
        for lead in leads:
            self.assertTrue(lead.target.startswith("http"))
            self.assertTrue(lead.false_positive_risk)
            self.assertEqual(lead.to_dict()["origin"], DERIVED)

    def test_infrastructure_pivots_are_built_for_domains(self):
        labels = {p["label"] for p in pivots.pivots_for_domain("example.test")}
        self.assertIn("WHOIS registration", labels)
        self.assertIn("Certificate transparency", labels)


# ---------------------------------------------------------------------------
# Capability: multi-model and confidence
# ---------------------------------------------------------------------------

class MultiModelTests(unittest.TestCase):
    def _check(self, *verdicts):
        return multimodel.CrossCheck(
            claim="A claim", sources=["https://a.test/"],
            verdicts=[multimodel.ModelVerdict(model=f"m{i}", verdict=v)
                      for i, v in enumerate(verdicts)],
        )

    def test_opposed_verdicts_are_contradictory_not_averaged(self):
        check = self._check(multimodel.SUPPORTED, multimodel.CONTRADICTED)
        self.assertEqual(check.agreement, "contradictory")
        result = multimodel.summarize_cross_checks([check])
        finding = result.findings[0]
        self.assertEqual(finding.check, "Model Disagreement")
        self.assertEqual(finding.priority, HIGH)
        self.assertEqual(finding.origin, MODEL)
        self.assertIn("no model's verdict has been adopted", finding.next_step)

    def test_unanimous_agreement_is_not_called_verification(self):
        check = self._check(multimodel.SUPPORTED, multimodel.SUPPORTED)
        self.assertEqual(check.agreement, "unanimous")
        finding = multimodel.summarize_cross_checks([check]).findings[0]
        self.assertIn("not verification", finding.next_step)

    def test_even_split_has_no_majority(self):
        check = self._check(multimodel.SUPPORTED, multimodel.INSUFFICIENT)
        self.assertIsNone(check.majority)

    def test_a_failed_model_does_not_lose_the_other_verdicts(self):
        check = multimodel.CrossCheck(claim="c", verdicts=[
            multimodel.ModelVerdict(model="a", verdict=multimodel.SUPPORTED),
            multimodel.ModelVerdict(model="b", verdict="", error="connection refused"),
            multimodel.ModelVerdict(model="c", verdict=multimodel.SUPPORTED),
        ])
        self.assertEqual(len(check.answered), 2)
        self.assertEqual(check.agreement, "unanimous")

    def test_unrecognized_verdict_is_an_error_not_a_vote(self):
        verdict = multimodel._parse_verdict("m", {"verdict": "probably", "confidence": 0.9})
        self.assertTrue(verdict.error)
        self.assertEqual(verdict.verdict, "")

    def test_cross_model_confidence_requires_more_than_one_model(self):
        self.assertEqual(cross_model_confidence(1, 1).value, 0.0)
        self.assertEqual(cross_model_confidence(2, 2).value, 1.0)

    def test_no_cross_check_requested_reports_cleanly(self):
        result = multimodel.summarize_cross_checks([])
        self.assertEqual(result.finding_count, 0)
        self.assertTrue(result.notes)


# ---------------------------------------------------------------------------
# Capability: evaluation
# ---------------------------------------------------------------------------

class EvaluationTests(unittest.TestCase):
    def test_ungrounded_entities_lower_entity_accuracy(self):
        grounded, _ = evaluation.score_entity_accuracy(
            {"key_entities": ["Acme Corp"]}, "A report about Acme Corp operations."
        )
        invented, failures = evaluation.score_entity_accuracy(
            {"key_entities": ["Acme Corp", "Nonexistent Holdings"]},
            "A report about Acme Corp operations.",
        )
        self.assertEqual(grounded, 1.0)
        self.assertLess(invented, 1.0)
        self.assertTrue(failures)

    def test_overstated_language_is_penalized(self):
        confident, failures = evaluation.score_confidence_language(
            {"summary": "This confirmed and verified report proves the subject is guilty."}
        )
        hedged, _ = evaluation.score_confidence_language(
            {"summary": "The page appears to indicate a possible connection, unverified."}
        )
        self.assertLess(confident, hedged)
        self.assertTrue(failures)

    def test_missing_schema_keys_lower_format_compliance(self):
        complete, _ = evaluation.score_format_compliance(
            {k: ([] if k in evaluation.LIST_KEYS else "x") for k in evaluation.REQUIRED_KEYS}
        )
        partial, failures = evaluation.score_format_compliance({"url": "u"})
        self.assertEqual(complete, 1.0)
        self.assertLess(partial, complete)
        self.assertTrue(failures)

    def test_vague_leads_lower_pivot_reasoning(self):
        vague, _ = evaluation.score_pivot_reasoning({"actionable_leads": ["investigate further"]})
        specific, _ = evaluation.score_pivot_reasoning(
            {"actionable_leads": ["Run WHOIS on example.test and compare the registrant"]}
        )
        self.assertLess(vague, specific)

    def test_weights_match_the_release_rubric_and_sum_to_one(self):
        self.assertEqual(evaluation.RUBRIC_WEIGHTS["entity_accuracy"], 0.30)
        self.assertEqual(evaluation.RUBRIC_WEIGHTS["confidence_language"], 0.25)
        self.assertAlmostEqual(sum(evaluation.RUBRIC_WEIGHTS.values()), 1.0)

    def test_run_evaluation_aggregates_failures(self):
        analyses = [
            {"url": "https://a.test/", "summary": "This confirmed report proves everything.",
             "key_entities": ["Invented Entity"], "actionable_leads": ["investigate further"]},
        ]
        result = evaluation.evaluate_run(analyses, lambda u: "unrelated page text", model="m")
        self.assertEqual(result.stats["evaluated"], 1)
        self.assertTrue(result.stats["dominant_failures"])
        self.assertLess(result.stats["mean_weighted_score"], 0.9)

    def test_evaluation_is_deterministic_across_calls(self):
        analysis = {"url": "https://a.test/", "summary": "Appears possible.",
                    "key_entities": ["Acme"], "actionable_leads": ["Check WHOIS for acme.test"]}
        first = evaluation.evaluate_analysis(analysis, "Acme page")
        second = evaluation.evaluate_analysis(analysis, "Acme page")
        self.assertEqual(first["weighted_score"], second["weighted_score"])
        self.assertEqual(first["method"], "deterministic_rubric")


# ---------------------------------------------------------------------------
# Capability: pipeline end to end
# ---------------------------------------------------------------------------

def _build_run(run_dir: str) -> None:
    """A minimal but realistic run directory."""
    safe_mkdir(os.path.join(run_dir, "pages_text"))
    safe_mkdir(os.path.join(run_dir, "analysis"))
    now = time.time()

    pages = [
        ("https://site.test/contact", "Contact", "Reach John Martinez at 816-555-0142. "
                                                 "Email jmartinez@site.test. Posted 2020-01-15."),
        ("https://site.test/about", "About", "Contact (816) 555-0142 or @jmartinez. "
                                             "Updated 2021-08-01. Internal host 10.0.0.5."),
        ("https://site.test/notice", "Notice", "As an AI language model, I cannot help with that."),
    ]
    for url, title, text in pages:
        with open(os.path.join(run_dir, "pages_text", f"{sha1(url)}.txt"), "w",
                  encoding="utf-8") as handle:
            handle.write(text)
        append_jsonl(os.path.join(run_dir, "urls_crawled.jsonl"), {
            "url": url, "status_code": 200, "fetched_at": now, "title": title,
            "text_len": len(text),
        })
        append_jsonl(os.path.join(run_dir, "indicators.jsonl"), {
            "url": url, "domain": "site.test", "domains": ["site.test", "pаypal.test"],
            "emails": ["jmartinez@site.test", "agent@agency.gov"],
            "phones": ["816-555-0142"] if "contact" in url else ["8165550142"],
            "urls": ["https://other.test/x"], "ip_addresses": ["10.0.0.5"],
            "btc_addresses": [], "eth_addresses": [], "social_handles": ["@jmartinez"],
        })
        append_jsonl(os.path.join(run_dir, "page_scores.jsonl"), {
            "url": url, "title": title, "score": 10.0, "summary": f"Summary of {title}",
            "risk_flags": [],
        })
        with open(os.path.join(run_dir, "analysis", f"{sha1(url)}.analysis.json"), "w",
                  encoding="utf-8") as handle:
            json.dump({
                "url": url, "title": title, "summary": "The page appears to list contacts.",
                "key_entities": ["John Martinez"], "key_locations": [], "key_dates": ["Feb 28, 2026"],
                "keywords": ["contact"], "risk_flags": [],
                "actionable_leads": ["Check WHOIS for site.test"],
            }, handle)


class PipelineTests(unittest.TestCase):
    def test_full_offline_analysis_produces_every_artifact(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _build_run(run_dir)
            output = analyze_run(
                run_dir,
                AnalysisOptions(evaluate=True, use_ollama=False, model="test-model"),
                ollama=None, run_id="t1", log=lambda m: None,
            )
            self.assertEqual(output.errors, [])
            for name in ("findings.jsonl", "hypotheses.jsonl", "leads.jsonl",
                         "correlations.jsonl", "timeline.jsonl", "analysis_summary.json"):
                self.assertTrue(os.path.exists(os.path.join(run_dir, name)), name)

            checks = {f.check for f in output.findings}
            self.assertIn("Unicode / Homoglyph", checks)          # Cyrillic domain
            self.assertIn("Sensitive Email Domain", checks)       # .gov address
            self.assertIn("Internal IP Exposure", checks)         # RFC1918
            self.assertIn("Generated-Content Fingerprint", checks)
            self.assertTrue(output.hypotheses)
            self.assertTrue(output.leads)

    def test_analysis_runs_with_ollama_disabled(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _build_run(run_dir)
            output = analyze_run(
                run_dir, AnalysisOptions(use_ollama=False, deep=True, cross_check_models=["x"]),
                ollama=None, run_id="t2", log=lambda m: None,
            )
            # deep and cross-check are silently inert without a model; nothing crashes.
            self.assertEqual(output.errors, [])
            self.assertTrue(output.findings)

    def test_empty_run_directory_is_reported_not_crashed(self):
        with tempfile.TemporaryDirectory() as run_dir:
            output = analyze_run(
                run_dir, AnalysisOptions(use_ollama=False), ollama=None, log=lambda m: None
            )
            self.assertTrue(output.errors)
            self.assertEqual(output.findings, [])

    def test_a_failing_stage_does_not_abort_the_pipeline(self):
        from osintai import pipeline as pipeline_module

        original = pipeline_module.patterns.check_homoglyphs
        pipeline_module.patterns.check_homoglyphs = lambda index: (_ for _ in ()).throw(
            RuntimeError("deliberate stage failure")
        )
        try:
            with tempfile.TemporaryDirectory() as run_dir:
                _build_run(run_dir)
                output = analyze_run(
                    run_dir, AnalysisOptions(use_ollama=False),
                    ollama=None, log=lambda m: None,
                )
                self.assertTrue(any("deliberate stage failure" in e for e in output.errors))
                self.assertTrue(output.findings)  # every other stage still ran
        finally:
            pipeline_module.patterns.check_homoglyphs = original

    def test_training_export_requires_evaluation(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _build_run(run_dir)
            output = analyze_run(
                run_dir, AnalysisOptions(use_ollama=False, training_export=True),
                ollama=None, log=lambda m: None,
            )
            self.assertTrue(any("requires --evaluate" in e for e in output.errors))
            self.assertNotIn("training_export", output.artifacts)

    def test_training_export_writes_portable_formats(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _build_run(run_dir)
            output = analyze_run(
                run_dir,
                AnalysisOptions(use_ollama=False, evaluate=True, training_export=True,
                                model="osint-tuned-v3:latest"),
                ollama=None, run_id="t3", log=lambda m: None,
            )
            export_dir = output.artifacts.get("training_export")
            self.assertTrue(export_dir and os.path.isdir(export_dir))
            manifest = json.loads(_read(os.path.join(export_dir, "manifest.json")))
            self.assertEqual(manifest["produced_by"], "OSINTai")
            self.assertEqual(manifest["rubric_weights"], evaluation.RUBRIC_WEIGHTS)
            with open(os.path.join(export_dir, "tasks.jsonl"), encoding="utf-8") as handle:
                for line in handle:
                    task = json.loads(line)
                    self.assertEqual(set(task) >= {"id", "type", "prompt", "rubric"}, True)

    def test_analysis_report_separates_observed_from_derived(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _build_run(run_dir)
            output = analyze_run(
                run_dir, AnalysisOptions(use_ollama=False), ollama=None, log=lambda m: None
            )
            path = write_analysis_report(run_dir, output, run_id="t4", scope={"seeds": 1})
            content = _read(path)
            self.assertIn("OBSERVED — PRESENT IN SOURCE MATERIAL", content)
            self.assertIn("DERIVED — COMPUTED FROM SOURCE MATERIAL", content)
            self.assertIn("MODEL-ASSISTED — LANGUAGE MODEL INTERPRETATION", content)
            self.assertIn("HYPOTHESES — NOT FINDINGS, NOT FACTS", content)
            self.assertIn("RECOMMENDED NEXT STEPS", content)

    def test_analysis_does_not_modify_crawl_artifacts(self):
        with tempfile.TemporaryDirectory() as run_dir:
            _build_run(run_dir)
            crawl_files = ["urls_crawled.jsonl", "indicators.jsonl", "page_scores.jsonl"]
            before = {name: _read(os.path.join(run_dir, name)) for name in crawl_files}
            analyze_run(run_dir, AnalysisOptions(use_ollama=False), ollama=None,
                        log=lambda m: None)
            for name in crawl_files:
                self.assertEqual(_read(os.path.join(run_dir, name)), before[name])


if __name__ == "__main__":
    unittest.main()
