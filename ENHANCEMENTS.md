# OSINTai enhancements

## Integrated in 4.2.0

All seven enhancement areas from the 4.1.0 follow-up list are implemented:

1. **Process-isolated deadlines.** Live HTML parsing, indicator extraction, hunt matching,
   and Simhash run in disposable spawn workers. Saved-page extraction, entity indexing,
   deterministic/model stages, and training export have deadlines. CPU timeouts, crashed
   children, cancellation, and large IPC results have offline tests. Workers are terminated
   and reaped. Raw HTML is retained before parsing, and failures are recorded. CLI controls:
   `--analysis-page-timeout` (30 seconds), `--analysis-stage-timeout` (120 seconds).
2. **Content-addressed extraction checkpoints.** `.extraction_cache/` keys include scanned
   text SHA-256, extractor implementation hash, character limit, and truncation state.
   Atomic JSON checkpoints carry schema/checksum validation and per-kind coverage counts.
   Repeated pages and resumed analyses reuse valid results. Cache writes failing does not
   discard successful extraction. Secret values and arbitrary JWT claims are excluded;
   secret-shaped values are also removed from cached indicator fields, including values
   beyond the findings cap. Reports reconstruct findings from counts and decode validity.
3. **Adversarial regex audit.** Email, ASCII-domain, credential, and JWT extraction consume
   maximal tokens or lines before bounded validation. Oversized malformed candidates cannot
   restart an unbounded suffix search. Unicode scanning remains linear. External-deadline
   tests cover repeated punctuation, failed domain/email suffixes, JWT-like strings, and
   long credential lines. Fixed detector limits and their omissions are reported.
4. **Model quality and bounded retry.** Results distinguish `ok`, `empty`, `invalid`,
   `missing`, `timed_out`, `error`, and `skipped`. Page attribution comes from saved file
   identity rather than model assertions. Manifests record model names, validated page
   counts, and optional stage response counts. `--retry-model RUN_ID --retry-limit 20
   --retry-timeout 60` retries unsuccessful/skipped saved pages through local Ollama,
   without fetching pages or overwriting original analyses. Later offline runs use the
   published `model_retry_latest.json` overlay.
5. **Hunt offsets and URL provenance.** Unicode expansion maps matches back to original
   start/end offsets. URL detection uses original text and rejects URLs crossing a snippet
   boundary. Indicator provenance identifies `html_attribute`, `page_prose`, and
   `html_source`; resolved relative HTML links are included.
6. **Bounded correlation and text caching.** `--correlation-pair-budget` defaults to
   100,000 examined co-occurrence pairs. Omitted pairs, oversized-page exclusions, and
   output truncation are explicit. Source membership uses sets, and identity evidence
   avoids repeatedly scanning a common handle's entire source list. Each text reader has
   a `--text-cache-bytes` LRU budget (16 MB default), accounting for string and entry
   overhead. Cache peaks, evictions, missing files, and truncation are reported.
7. **Transactional analysis publication.** A hidden incomplete directory is populated
   and validated before an atomic rename publishes an immutable `analysis_*/` bundle.
   The bundle includes the human report, JSON/JSONL results, summary, manifest, and optional
   training export. `analysis_latest.json` advances only after successful publication.
   Attempt status records running/failed/completed state, and manifests retain full source
   hashes and options. Source changes during analysis prevent publication. File contents
   are flushed; POSIX directory metadata is fsynced. Original captures and prior bundles
   remain intact. Completed publication may still report partial analytical coverage.

The existing 4.1.0 fixes are retained: Unicode scanning, offline recovery, bounded text
reads, failure isolation, clean interruption, HTML text boundaries, complete summaries,
empty artifacts, numeric validation, and explicit profile overrides.

## Verification and performance

See `tests/test_enhancements.py` for deterministic offline acceptance checks and
`tests/benchmark_analysis.py` for saved-crawl runtime and memory measurements. CI now
runs the release gate on macOS, Linux, and Windows. Local verification was performed on
macOS with Python 3.12.

Measured results are recorded in `BENCHMARKS.md`. RSS figures separate parent memory
from the maximum child RSS; they are not a measured concurrent process-tree total.

Scanning is O(N) for bounded token validators and fixed extraction caps. Entity indexing
is expected O(S), with S source/indicator observations. Correlation generation is bounded
by O(S + B), followed by O(K log K) ordering of K candidates, where B is the pair budget.
Core retained analysis memory is O(S + E + B + C + R + L): E entities, C the text-cache budget,
R retained result rows, and L the per-job input bound. Disposable workers add serialization copies and startup cost.
Hunt searches cost O(TN) for T terms, with at most 500 reported hits; Unicode offset mapping
uses O(N) space only when lowercasing expands characters. Full source hashing streams
files with a 1 MB buffer. Thread timeouts and unbounded caches were rejected because they
cannot provide containment and predictable memory use.

## Recommended next work

1. **Public-suffix-aware domain families.** `_registrable()` still uses the last two
   labels; names beneath suffixes such as `co.uk` can be incorrectly grouped. Bundle a
   versioned Public Suffix List for deterministic offline grouping and ownership caveats.
2. **Cache retention and quotas.** Add explicit age/size-based pruning for extraction
   checkpoints and old report/retry bundles, preserving referenced evidence and active
   attempts. Current cache memory is bounded, but disk retention is intentionally additive.
3. **Typed streaming artifact ingestion.** Stream large JSONL files and validate record
   schemas with line-level corruption counts. Current loaders materialize metadata and
   silently skip malformed JSON lines; text-cache limits do not bound total index memory.
4. **Reduce process startup overhead.** Benchmark a supervised, recyclable worker design
   that preserves hard per-job termination and isolation. The current spawn-per-job design
   is portable and simple, but cold runs pay startup cost for every distinct page.
5. **More precise reproducibility and memory telemetry.** Inject a reference clock for
   temporal analysis and generated timestamps; measure concurrent process-tree RSS, and
   add Windows benchmark memory collection. Validate filesystem crash durability on the
   supported filesystems; Windows does not provide POSIX directory-fsync semantics here.
6. **Raw-only parsing recovery.** Offer an explicit offline command to reparse preserved
   HTML from live extraction failures. Current `--analyze-only` consumes saved page text
   and reports raw-only failures rather than reconstructing missing text automatically.
