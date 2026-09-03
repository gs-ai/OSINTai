# Changelog

All notable changes to OSINTai are recorded here.

## [Unreleased]

### Added

- **Proxy harvester** (`run_proxy_harvester.py`, `src/osintai/proxyharvest/`) —
  continuous discovery, validation, and evidence-graded classification of public
  free proxies, exporting a working set the crawler consumes via `--proxies`.
  - Source registry with an `L(s)` language heuristic that keeps raw text/JSON
    endpoints on the static httpx path and escalates to Playwright only for
    sources that genuinely render client-side (`--enable-js`, optional).
  - Parsers for raw text (`ip:port`, `ip|port`, scheme-prefixed), JSON (nested
    and packed shapes, JSON-lines fallback), and HTML tables, rejecting private,
    loopback, link-local, reserved, and documentation-range addresses.
  - Concurrent validation with a latency budget, echo-schema integrity checking
    that rejects intercepted or injected bodies, `407` exclusion under the
    no-auth constraint, and a second confirmation probe against a different
    endpoint that keeps the worse of the two readings.
  - Anonymity grading (`transparent` / `anonymous` / `elite`) against a measured
    baseline of the harvester's own egress address.
  - Evidence-graded network classification with an explicit precedence order,
    a per-row `classification_basis`, and confidence scores that never assert
    certainty. Cloud/hosting ASN evidence overrides consumer-looking PTR text.
    Optional operator-supplied CIDR→ASN table via `--asn-table`.
  - SQLite persistence for candidates, validations, the working set, per-source
    statistics, and cycle metrics, with failure-count retirement and automatic
    restoration of returning proxies.
  - Randomized `T ~ U[19,23]` minute cycle, checkpointed CSV/JSON/JSONL/TXT
    exports with a manifest, yield-based abort, and cooperative SIGINT/SIGTERM
    shutdown that always writes a final export.
  - Live CLI status (phase, `|W|`, remaining `T-t`, next export), with
    `--json-status` for supervision and `--quiet` for unattended runs.
  - Request hygiene: coherent per-UA header sets, inter-source jitter, robots.txt
    handling, and TLS cipher-order variation that never disables verification or
    lowers the TLS 1.2 floor.
  - Feedback chaining of validated proxies into the harvester's own egress,
    **off by default** and restricted to fresh elite-grade entries when enabled.
  - Alternate modes: `--dry-run`, `--validate-file`, `--list-sources`, `--stats`.
- `config.example.json` and `config.example.yaml` for harvester configuration.
- `requirements-proxyharvest.txt` for optional extras (SOCKS, Playwright, YAML),
  kept out of `requirements.txt` so the release gate keeps auditing a small
  locked runtime surface.
- `docs/PROXY_HARVESTER.md` covering the constraint analysis, cycle mechanics,
  classification precedence, ASN table format, feedback-loop risk, CLI reference,
  and runbook.
- `tests/test_proxy_harvester.py` — 73 offline test cases covering parsing,
  language dispatch, source config validation, anonymity grading, validation
  behaviour under interception and auth-required responses, classification
  precedence, stealth constraints, robots handling, store churn, exports, and
  CLI argument validation. Network paths run through `httpx.MockTransport`.

### Changed

- `HarvestStore.finish_cycle` uses a fixed statement with `COALESCE` rather than
  assembling its `UPDATE` clause, so no caller-supplied name reaches SQL text.
- Release gate additionally compiles, lints, and security-scans the new entry
  point and subpackage, and verifies the harvester CLI starts and lists sources.
