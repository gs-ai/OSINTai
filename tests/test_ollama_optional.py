"""Ollama is an opt-in integration: off by default, enabled only by explicit flags."""
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from osintai import cli
from osintai.pipeline import AnalysisOptions


def _run(*flags):
    with patch.object(sys, "argv", ["run_osintai.py", "--analyze-only=saved", *flags]), \
         patch("osintai.cli._analyze_saved_run") as recover:
        cli.main()
    return recover.call_args.args[0]


class OllamaOptionalTests(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertTrue(_run().no_ollama)
        self.assertFalse(AnalysisOptions().use_ollama)

    def test_enabled_only_by_flag(self):
        self.assertFalse(_run("--ollama").no_ollama)

    def test_legacy_no_ollama_flag_still_accepted(self):
        self.assertTrue(_run("--no-ollama").no_ollama)

    def test_model_modes_require_explicit_opt_in(self):
        for flags in (["--deep"], ["--cross-check=m"], ["--experimental-recursive=1"],
                      ["--ollama", "--no-ollama"]):
            with self.subTest(flags=flags), \
                 patch.object(sys, "argv", ["run_osintai.py", "--analyze-only=saved", *flags]), \
                 patch("osintai.cli._analyze_saved_run") as recover, \
                 contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    cli.main()
                self.assertEqual(raised.exception.code, 2)
                recover.assert_not_called()

    def test_default_crawl_never_constructs_client(self):
        with patch.object(sys, "argv", ["run_osintai.py", "--seed", "https://example.com",
                                        "--max", "1", "--depth", "0", "--no-analysis"]), \
             patch("osintai.cli.OllamaAPI", side_effect=AssertionError("ollama contacted")), \
             patch("osintai.crawler.OllamaAPI", side_effect=AssertionError("ollama contacted")), \
             patch("osintai.cli.AsyncCrawler") as crawler, \
             patch("osintai.cli.asyncio.run", side_effect=RuntimeError("stop before network")), \
             patch("osintai.cli.safe_mkdir"), patch("osintai.cli.write_json"), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                cli.main()
        self.assertIs(crawler.call_args.kwargs["use_ollama"], False)


if __name__ == "__main__":
    unittest.main()
