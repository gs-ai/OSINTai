"""Bounded regression checks for the regex hang and saved-run recovery."""
import contextlib
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osintai import __version__, cli, entities
from osintai.extractor import Extractor
from osintai.hunt import hunt_leads
from osintai.pipeline import AnalysisOptions, analyze_run
from osintai.storage import sha1


def _bad_extraction(text):
    raise ValueError("bad page")


class RecoveryTests(unittest.TestCase):
    def test_adversarial_domain_scan_has_deadline(self):
        # An external deadline prevents a reintroduced regex bug hanging CI.
        code = """
from osintai.entities import extract_extended, unicode_domains
assert not list(unicode_domains('a' * 1000000))
assert not list(unicode_domains(('a.' * 500000) + '!'))
assert 'раypal.com' in extract_extended('a' * 10000 + ' раypal.com')['unicode_domains']
"""
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
        subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=10)

    def test_unicode_domains_and_boundaries(self):
        actual = set(entities.unicode_domains(
            'ascii.com раypal.com münich.de example..рф -bad.рф zero\u200bwidth.com'
        ))
        self.assertEqual(actual, {'раypal.com', 'münich.de', 'zero\u200bwidth.com'})

    def test_html_elements_do_not_glue_urls(self):
        _, text = Extractor().html_to_text(
            '<p>https://example.com/api.md</p><nav>Product</nav><span>Postman</span>'
        )
        self.assertEqual(text, 'https://example.com/api.md\nProduct\nPostman')

    def build_run(self, directory):
        root = Path(directory)
        (root / 'pages_text').mkdir()
        url = 'https://example.test/'
        (root / 'urls_crawled.jsonl').write_text(json.dumps({'url': url}) + '\n')
        (root / 'pages_text' / (sha1(url) + '.txt')).write_text('a' * 1000)
        return root

    def test_recovery_preserves_source_and_reports_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_run(directory)
            before = {p: p.read_bytes() for p in root.rglob('*') if p.is_file()}
            logs = []
            output = analyze_run(str(root), AnalysisOptions(use_ollama=False, max_text_chars=100),
                                 output_dir=str(root / 'recovered'), log=logs.append)
            self.assertEqual(output.stats['pages_text_truncated'], 1)
            self.assertTrue(any('[SCAN] 1/1' in message for message in logs))
            summary = json.loads(Path(output.artifacts['analysis_summary']).read_text())
            self.assertEqual(summary['stats'], output.stats)
            for path in output.artifacts.values():
                self.assertTrue(Path(path).exists(), path)
            for path, content in before.items():
                self.assertEqual(path.read_bytes(), content)

    def test_extraction_failure_is_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.build_run(directory)
            with patch('osintai.pipeline.extract_checkpoint', _bad_extraction):
                output = analyze_run(str(root), AnalysisOptions(use_ollama=False))
            self.assertTrue(any('bad page' in error for error in output.errors))
            self.assertIn('analysis_summary', output.artifacts)

    def test_cli_recovery_never_constructs_network_clients(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / 'data' / 'runs' / 'saved'
            run.mkdir(parents=True)
            self.build_run(run)
            args = type('Args', (), dict(analyze_only='saved', no_analysis=False, deep=False,
                cross_check='', experimental_recursive=0, evaluate=False, training_export=False,
                gap_days=90, leads_per_kind=10, analysis_max_chars=200000))()
            with patch('osintai.cli.OllamaAPI', side_effect=AssertionError('network')), \
                 patch('osintai.cli.AsyncCrawler', side_effect=AssertionError('crawl')), \
                 contextlib.redirect_stdout(io.StringIO()):
                cli._analyze_saved_run(args, argparse.ArgumentParser(), str(root))
                cli._analyze_saved_run(args, argparse.ArgumentParser(), str(root))
            self.assertEqual(len(list(run.glob('reanalysis_*/analysis_*/analysis_report.txt'))), 2)

    def test_interrupt_is_clean(self):
        with patch('osintai.cli._main', side_effect=KeyboardInterrupt), \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            with self.assertRaises(SystemExit) as raised:
                cli.main()
        self.assertEqual(raised.exception.code, 130)
        self.assertIn('--analyze-only', stderr.getvalue())

    def test_profile_respects_equals_syntax(self):
        with patch.object(sys, 'argv', ['run_osintai.py', '--profile=survey', '--max=12',
                                      '--depth=1', '--analyze-only=saved']), \
             patch('osintai.cli._analyze_saved_run') as recover:
            cli.main()
        args = recover.call_args.args[0]
        self.assertEqual(args.max, 12)
        self.assertEqual(args.depth, 1)

    def test_invalid_limits_fail_before_recovery(self):
        for flag in ('--analysis-max-chars=0', '--concurrency=0', '--depth=-1'):
            with self.subTest(flag=flag), \
                 patch.object(sys, 'argv', ['run_osintai.py', '--analyze-only=saved', flag]), \
                 patch('osintai.cli._analyze_saved_run') as recover, \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    cli.main()
                self.assertEqual(raised.exception.code, 2)
                recover.assert_not_called()

    def test_hunt_empty_terms_and_global_hit_limit(self):
        self.assertEqual(hunt_leads('text', [''])['hits'], [])
        result = hunt_leads('api ' * 600, ['api', 'api'])
        self.assertEqual(len(result['hits']), 500)

    def test_readme_version_matches_package(self):
        readme = (Path(__file__).resolve().parents[1] / 'README.md').read_text()
        self.assertIn(f'# OSINTai v{__version__} ', readme)
        self.assertIn(f'### v{__version__} (', readme)
