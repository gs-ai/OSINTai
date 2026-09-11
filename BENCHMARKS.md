# OSINTai 4.2.0 offline benchmarks

Measured on 2026-09-10 using Python 3.12.13, Darwin
arm64. These are single-run observations, not statistical guarantees.
No page fetching or model calls were performed. Source captures and existing reports
were preserved; the benchmark produced new extraction checkpoints and report bundles.

## Saved crawls

Default analysis settings: 200,000 characters per page; 16 MB text cache per reader;
100,000 co-occurrence candidate-pair budget; 30-second page and 120-second stage deadlines.
Timing includes source hashing, worker startup, analysis, report validation, and publication.

| Saved run | Cache | Pages | Elapsed | Cache hits/misses | Parent peak RSS | Maximum child RSS |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 20260909_212714 | cold | 152 | 18.133 s | 0/152 | 91.9 MiB | 84.4 MiB |
| 20260909_212714 | warm | 152 | 1.644 s | 152/0 | 86.8 MiB | 84.4 MiB |
| 20260717_144145 | cold | 159 | 18.923 s | 2/157 | 85.5 MiB | 92.6 MiB |

The 159-page cold run reused two identical page contents within the same invocation.
RSS is reported separately for the parent and the largest individual child; summing the
columns is not a measurement of simultaneous process-tree memory. Warm means extraction
checkpoints were reused, not that every filesystem or OS cache was controlled.

Both crawls explicitly report partial analytical coverage. The 152-page crawl excluded
92,369 potential pairs on pages exceeding the 60-identifier pairing threshold. The
159-page crawl excluded 161,328 such pairs, omitted 25,125 low-ranked correlation rows
at the output cap, and recorded 46 temporal parsing errors from source date values.
Neither run exhausted its candidate-pair budget. Publication succeeded and these limits
and errors remain visible in each bundle's summary and report.

## Boilerplate fixture

The synthetic fixture has 10,000 pages, four shared footer identifiers, and one
unique email/handle pair per page. All four footer identifiers are excluded from pairing.

- Entity indexing: **0.053 seconds**.
- Correlation: **0.079 seconds**.
- Examined co-occurrence pairs: **10,000**.
- Pairs omitted by budget: **0**.
- Parent peak RSS: **60.8 MiB**.

## Reproduction

Run from the repository using its Python environment. Benchmark memory collection uses
`resource`, available on macOS/Linux; the unit-test CI matrix also covers Windows.

```bash
python tests/benchmark_analysis.py RUN_ID --output .test-tmp/benchmark-cold.json
python tests/benchmark_analysis.py RUN_ID --output .test-tmp/benchmark-warm.json
python tests/benchmark_correlation.py --pages 10000 --pair-budget 100000
```

A run is cold only if no matching extractor-version/content checkpoints exist. No
benchmark deletes prior checkpoints or source material to manufacture a cold run.

## Verification

All **119 offline tests** passed locally with `ResourceWarning` treated as an error.
Correctness lint, Bandit at the release gate's severity/confidence thresholds, compilation,
CLI version/help checks, and whitespace checks passed. The release workflow runs the same
gate on Linux, macOS, and Windows.
