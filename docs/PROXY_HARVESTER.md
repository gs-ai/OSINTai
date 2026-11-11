# Proxy Harvester

Continuous discovery, validation, and evidence-graded classification of public
free proxies, with a persistent working set and scheduled exports.

**Entry point:** `run_proxy_harvester.py`
**Package:** `src/osintai/proxyharvest/`

---

## 1. Read this first: what this tool does and does not produce

This module was specified as a "residential proxy harvester." It is not one, and
no tool operating under the stated constraints can be one. The constraints as
given were:

1. true residential IPs (ISP-assigned consumer/mobile lines),
2. no authentication and no account signup,
3. sourced from public free lists,
4. autonomous, continuous operation.

Constraints 1 and 2 are jointly unsatisfiable, for a reason that is structural
rather than technical:

- **Consented residential bandwidth is a metered commercial product.** Every
  provider that lawfully resells opt-in residential bandwidth gates it behind an
  account and per-gigabyte billing, because that is how they pay the people whose
  bandwidth is being resold. Free tiers exist (Webshare's 10 proxies / 1 GB per
  month, for example) but all require signup, which violates constraint 2.
- **"Residential" on a free public list is an unverified label.** It is derived
  from an ASN or geolocation lookup by whoever built the list, is frequently
  wrong, and is stale within hours. It is not a subscriber-line record.
- **Unconsented residential exit nodes exist and are a liability, not a
  resource.** Open residential proxies commonly come from compromised routers,
  IoT devices, and SDK-bundled malware. The FBI has issued public advisories on
  exactly this. Routing investigative traffic through a device whose owner never
  consented is a problem regardless of whether the tool that found it was clever.

Public lists yield **open proxies** — overwhelmingly datacenter, misconfigured
corporate egress, and short-lived hosts. Reported working rates for these lists
run roughly 2–15%, and a proxy that validates now is frequently dead within the
hour.

**So the module does the defensible version of the job:**

- It harvests, validates, and scores public free proxies honestly.
- It labels network type as **evidence-graded indication**, never as fact. The
  vocabulary is `residential_indicated`, `mobile_indicated`, `datacenter`,
  `hosting`, `unknown` — and every label carries a `classification_basis` string
  naming the signals that fired, plus a confidence score that never reaches 1.0.
- It treats its own output as **disposable test infrastructure**, not as
  operational anonymity infrastructure.

If you need real residential egress for professional work, the honest path is a
paid provider with a documented consent model and an auditable ToS. That is a
procurement decision, not a scraping problem.

### Operational cautions

| Risk | Why it matters here |
|---|---|
| Traffic interception | You do not control these hosts. Assume every plaintext request is logged and may be altered. The validator rejects proxies that alter the echo body, but that only catches the clumsy ones. |
| Case-data exposure | Never route authenticated sessions, client identifiers, subject names, or case-linked queries through a harvested proxy. |
| Attribution damage | An exit shared with abusive traffic can taint your own request history and get source IPs blocklisted. |
| Consent | An open residential-looking exit may be a compromised device. Yield alone is not authorization. |
| Source terms | Raw list endpoints on code hosts are published for consumption. Ordinary proxy-list *websites* frequently prohibit automated collection. Check before enabling one. |
| Evidentiary integrity | Do not collect anything intended as evidence through an uncontrolled proxy. Provenance you cannot attest to is provenance you cannot defend. |

---

## 2. Install

The harvester runs on the project's pinned requirements with no additions:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Optional capabilities live in a separate file, deliberately kept out of the
audited runtime set:

```bash
pip install -r requirements-proxyharvest.txt   # socks, playwright, yaml
python -m playwright install chromium          # only if using --enable-js
```

| Extra | Unlocks | Without it |
|---|---|---|
| `httpx[socks]` | SOCKS4/SOCKS5 validation | socks candidates are reported **skipped**, not failed |
| `playwright` | `--enable-js` rendered sources | JS sources are skipped with a stated reason |
| `PyYAML` | YAML config files | use `config.example.json` instead |

---

## 3. Quick start

```bash
# See what the configured sources yield, without sending a single probe.
python run_proxy_harvester.py --dry-run

# One full cycle: harvest, validate, classify, export.
python run_proxy_harvester.py --once --export-dir data/proxies

# Continuous operation on the specified 19-23 minute cycle.
python run_proxy_harvester.py --export-dir data/proxies

# Validate a list you already have, no harvesting.
python run_proxy_harvester.py --validate-file mylist.txt

# Feed the result to the main crawler.
python run_osintai.py --seed https://example.com \
    --proxies data/proxies/working_set_latest.txt
```

Stop with Ctrl-C or `SIGTERM`. The loop finishes its current phase and writes a
final export rather than discarding the cycle.

---

## 4. The cycle

Each cycle samples an interval `T ~ U[19, 23]` minutes (configurable) and runs:

```
harvest  -> fetch each enabled source, language-dispatched
parse    -> extract and de-duplicate (ip, port, protocol)
validate -> concurrent probes; two-phase confirmation
classify -> ASN + PTR evidence for each passing exit
persist  -> update working set W in SQLite; retire dead entries
export   -> CSV / JSON / JSONL / TXT + manifest at checkpoints
wait     -> sleep the remainder of T, interruptibly
```

### Language dispatch, `L(s)`

| Condition | Path |
|---|---|
| `renderer` declared `python` or `js` | honoured as declared |
| `kind` is `text` or `json` | Python (httpx) |
| static body contains ≥5 parseable endpoints | Python — a browser adds nothing |
| SPA marker present and fewer than 10 table rows | JS (Playwright) |
| ≥5 `<script>` tags and zero endpoints | JS (Playwright) |
| otherwise | Python |

The built-in source set is entirely raw text/JSON, so the Python path handles all
of it and Playwright is never needed by default. Rendering is opt-in
(`--enable-js`) because a browser per source is a large cost for a page that
usually did not need one.

### Validation

A candidate joins `W` only if **all** of the following hold:

1. Answers within the connect and read timeouts.
2. Returns HTTP 200. A `407` is treated as a hard exclusion — an authenticated
   proxy fails the no-auth constraint by definition.
3. Body parses as the echo endpoint's expected JSON shape. Anything else is
   recorded as *possible interception* and rejected — this is what catches
   captive portals, ad injection, and SSL-stripping middleboxes.
4. Latency is within `--max-latency`.
5. Anonymity grade meets `--min-anonymity`.
6. **Repeats all of the above on a second probe against a different echo
   endpoint** (unless `--no-confirm`). This is the check that removes proxies
   which answer once and die, and proxies that cached a single response.

When the two probes disagree, the harvester keeps the **worse** reading — the
slower latency and the weaker anonymity grade. Planning against the optimistic
number is how a pool looks better than it is.

### Anonymity grading

Grading needs a baseline: the harvester fetches its own egress address directly
at startup. Without that baseline a proxy that forwards your real address cannot
be distinguished from one that does not, so the run warns and grades
conservatively.

| Grade | Meaning |
|---|---|
| `transparent` | your address is disclosed, via `origin` or a forwarding header |
| `anonymous` | a proxy hop is disclosed (`Via`, `X-Forwarded-For`, chained origin), your address is not |
| `elite` | no proxy disclosure and no leak of your address |

### Classification, and how far to trust it

Precedence, highest-confidence first:

1. **Known cloud/hosting ASN** → `datacenter`, confidence 0.9. Dispositive: it
   overrides consumer-looking PTR text, and the override is recorded in the
   basis string.
2. **AS organisation name matching hosting terms** → `hosting`, 0.7.
3. **PTR datacenter tokens** (`compute.amazonaws.com`, `vps`, `colo`, …) →
   `datacenter`, 0.45–0.6.
4. **PTR mobile-carrier tokens** → `mobile_indicated`, 0.4–0.55.
5. **PTR consumer-access tokens** (`hsd1`, `dsl`, `dynamic`, `comcast`, …) →
   `residential_indicated`, **0.35–0.65**, always with the note that PTR text is
   operator-controlled and requires confirmation.
6. **Nothing matched** → `unknown`, 0.0, with the reason stated (no ASN table
   loaded, no PTR resolved).

The ceiling on a residential read is deliberate. Without an ASN table the tool
says so in the basis rather than quietly guessing.

**ASN table format** — supply your own via `--asn-table`, so the tool stays
offline-capable and never ships stale routing data:

```csv
cidr,asn,org,country
45.63.0.0/16,20473,The Constant Company,US
```

CSV or TSV, headerless or headed, longest-prefix match wins. Build one from a
public routing dump, an RIR extract, or a MaxMind ASN CSV export.

### Working set and churn

`W` lives in SQLite. Each cycle re-probes the existing set before new candidates,
so `W` reflects live state rather than accumulated history. A member that fails
`--retire-after` consecutive cycles (default 3) is retired: a soft delete that
keeps the row for churn analysis but removes it from `W` and from exports. A
retired proxy that comes back is automatically restored.

### Yield-based abort

`--yield-abort 0.02` stops the run after `--yield-abort-cycles` consecutive
cycles below a 2% pass rate. A source set that has stopped producing is a reason
to stop spending bandwidth, not a reason to keep looping.

---

## 5. Feedback loop risk (`--allow-chaining`)

The specification called for harvested proxies to be fed back as egress for the
harvester itself. That is implemented, and it is **off by default**.

Enabling it means your source fetches egress through hosts you do not control and
have not vetted. Concretely:

- Every fetched source body becomes attacker-influenceable input. A hostile exit
  can inject candidates of its choosing into your working set.
- A transparent or stale proxy leaks the harvester rather than protecting it.
- Sources that blocklist abusive proxy IPs will blocklist you along with them.

When enabled, the rotator only uses entries that are `elite`-grade and validated
within the last 15 minutes, and it prints a warning on first use. Those limits
reduce the blast radius; they do not remove it. Leave it off unless you have a
specific reason and have accepted the consequences.

---

## 6. CLI reference

| Flag | Default | Purpose |
|---|---|---|
| `--config` | — | JSON config (YAML with PyYAML) |
| `--once` / `--cycles N` | until signalled | run scope |
| `--interval-min` / `--interval-max` | 19 / 23 min | cycle window `T ~ U[a,b]` |
| `--db` | `data/proxies/harvest.sqlite` | persistent state |
| `--export-dir` | `data/proxies` | export destination |
| `--formats` | `csv,json,txt` | any of `csv,json,jsonl,txt` |
| `--export-every N` | 1 | export cadence in cycles |
| `--concurrency` | 60 | concurrent probes |
| `--timeout` | 8.0 s | probe timeout |
| `--max-latency` | 6000 ms | latency ceiling |
| `--min-anonymity` | `anonymous` | `transparent`/`anonymous`/`elite` |
| `--no-confirm` | off | skip the second probe (faster, less reliable) |
| `--echo-url` | httpbin, postman-echo | repeatable; JSON echo endpoints |
| `--no-revalidate` | off | do not re-probe `W` each cycle |
| `--retire-after` | 3 | failures before leaving `W` |
| `--asn-table` | — | CIDR→ASN CSV/TSV |
| `--no-ptr` | off | skip reverse DNS |
| `--ua` | `user_agents.txt` | user-agent pool |
| `--min-delay` / `--max-delay` | 1.5 / 4.5 s | inter-source jitter |
| `--enable-js` | off | allow Playwright rendering |
| `--ignore-robots` | off | skip robots.txt (you assume responsibility) |
| `--allow-chaining` | off | route harvest traffic through `W` |
| `--no-tls-rotation` | off | disable cipher-order variation |
| `--yield-abort` / `--yield-abort-cycles` | 0 / 3 | low-yield abort |
| `--json-status` / `--quiet` | off | machine-readable / silent status |
| `--list-sources` / `--dry-run` / `--stats` | — | inspection modes |
| `--validate-file` | — | validate an existing list, no harvest |

### Status line

```
cycle 3  phase=validate  |W|=42  cand=8818  pass=42/860 (4.9%)  T-t=14m22s  export in 14m22s  probe 600/860
```

Redrawn in place on a TTY, appended line-by-line when piped, or one JSON object
per state change with `--json-status`.

### TLS note

`--no-tls-rotation` disables *cipher-suite ordering* variation only. Certificate
verification and hostname checking are always on, TLS 1.2 is always the floor,
and the rotation pool contains only forward-secret AEAD suites. There is no flag
that disables TLS verification, by design.

---

## 7. Output

```
data/proxies/
├── harvest.sqlite                    # candidates, validations, W, cycles, per-source stats
├── working_set_20260903_142530.csv   # stamped snapshot
├── working_set_latest.csv            # stable path for downstream consumers
├── working_set_latest.json           # rows + manifest
├── working_set_latest.txt            # scheme://ip:port, feeds --proxies
└── manifest_20260903_142530.json     # counts, latency stats, classification notice
```

Export columns: `key, ip, port, protocol, source_id, latency_ms, anonymity,
exit_ip, network_class, classification_confidence, classification_basis, asn,
as_org, country, ptr, first_seen, last_ok, ok_count, fail_count`.

Every JSON export embeds the classification notice. If you hand an export to
someone else, hand them the manifest with it — the `network_class` column is the
one most likely to be misread as a finding.

---

## 8. Runbook

**Nothing validates (0% yield).** Expected in restricted-egress environments: a
validator needs direct outbound TCP to arbitrary IPs and ports. Check with
`curl -x http://IP:PORT https://httpbin.org/get`. If that fails too, the
environment is the constraint, not the tool.

**"could not determine local egress address."** The echo endpoints are
unreachable. Anonymity grading still runs, but `transparent` proxies may be
graded `anonymous`. Set a reachable `--echo-url` returning JSON with `headers`
and `origin`.

**All SOCKS candidates skipped.** `pip install "httpx[socks]"`.

**A source reports "needs JS rendering".** Add `--enable-js` and install
Playwright, or set that source's `renderer` explicitly in config.

**Yield collapses to near zero across cycles.** Normal for public lists. Check
`--stats` and the `source_stats` table for which sources stopped producing, then
prune them. Set `--yield-abort` so unattended runs stop themselves.

**Database locked.** One harvester per `--db`. Use separate database files for
concurrent runs.

**Disk growth.** `validations` grows by roughly `|batch|` rows per cycle. For
long unattended runs, prune periodically:

```sql
DELETE FROM validations WHERE checked_at < strftime('%s','now') - 604800;
```

---

## 9. Module map

| File | Responsibility |
|---|---|
| `models.py` | record types, protocol/IP validity, classification vocabulary |
| `sources.py` | source registry, config loading, `L(s)` language heuristic |
| `parsers.py` | text / JSON / HTML candidate extraction, de-duplication |
| `harvest.py` | source fetching, robots handling, Playwright dispatch |
| `validate.py` | concurrent probes, anonymity grading, integrity/confirmation |
| `classify.py` | ASN table, PTR heuristics, evidence-graded classification |
| `store.py` | SQLite persistence, working set, churn, cycle metrics |
| `export.py` | CSV/JSON/JSONL/TXT exports and manifest |
| `cycle.py` | cycle orchestration, signal handling, yield abort |
| `status.py` | live CLI status rendering |
| `cli.py` | argument parsing and mode dispatch |

Tests: `tests/test_proxy_harvester.py` (73 cases, fully offline — network paths
are exercised through `httpx.MockTransport`).

```bash
python -m unittest tests.test_proxy_harvester -v
```
