# RootIQ

Root-cause analysis for automated test failures. RootIQ runs a Pytest suite,
collects evidence from several sources, fingerprints failures, and produces a
diagnosis that cites the evidence behind it, with alternatives and next tests.

![CI](https://github.com/PriyanshuKhandelwal22/rootiq/actions/workflows/ci.yml/badge.svg)

The design rule: **the AI is not the source of truth.** Raw evidence is kept,
deterministic checks run first, and every diagnosis is scored against faults
whose real cause is known.

## How it works

```
Pytest run
   |
   v
Evidence collectors: JUnit results, CPU/memory, socket outcomes,
HTTP status/body, native process exit status, loopback + outbound
packet capture (Scapy/Npcap)
   |
   v
Normalizer -> fingerprint (error type + template + project-code frame)
   |
   +--> Rule engine (observed evidence first, error text as fallback)
   +--> History (SQLite) + TF-IDF similar-failure retrieval
   +--> LLM reasoner (optional, schema-validated, evidence-ID citations)
   |
   v
Diagnosis: root cause, confidence, evidence IDs, alternatives, next tests
   |
   v
CLI, read-only REST API, dashboard
```

## Setup (Windows, Python 3.11+)

```cmd
git clone https://github.com/PriyanshuKhandelwal22/rootiq.git
cd rootiq
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Optional pieces:

- Packet capture needs [Npcap](https://npcap.com) installed in WinPcap
  API-compatible mode. Without it, capture is skipped and the run still works.
- The native crash test needs `gcc` (for example MinGW-w64 via
  `winget install BrechtSanders.WinLibs.POSIX.UCRT`).
- The LLM reasoner needs `GEMINI_API_KEY` set as an environment variable.
  Never put keys in files.

## Usage

```cmd
python -m rootiq run                    # run the demo suite, save evidence, store history
python -m rootiq analyze run_001        # diagnose every failure in a run
python -m rootiq flaky                  # flaky-test report from run history
python -m rootiq similar test_http_404  # nearest past failures (TF-IDF)
python -m rootiq benchmark sample       # score diagnoses against known causes
python -m rootiq benchmark-retrieval    # retrieval-only baseline
python -m rootiq llm run_051 test_http_404   # LLM diagnosis of one failure
python -m uvicorn rootiq.api:app        # API + dashboard on 127.0.0.1:8000
```

The demo suite fails on purpose. Each failing test injects a known fault
(closed port, silent server, dropped SYN, HTTP 4xx/5xx, partial body, reset,
DNS failure, native crash, and so on), and the known cause is stored in
`benchmark/cases.json`.

## Evaluation

Labels were committed **before** the rules that diagnose them. The first run of
each new batch is recorded as a baseline, and only then are rules added.

| Batch | Before rules | After rules |
|---|---|---|
| real (3) | 0/3 using error text only | 3/3 |
| held-out batches 1-4 (12 faults) | **1/12**, 0 confident wrong | 11/12 |
| simulated (7) | 7/7 | 7/7 |

- The **before-rules column on held-out faults is the figure to read as
  generalization.** The after-rules column is a regression check, because the
  rules were written after seeing those faults.
- Where no rule applied, the engine answered "unknown" instead of guessing:
  no confident wrong answers in any batch.
- The simulated tests were written together with the rules, so that row is
  circular and shown only for completeness.
- *Before-rules figures were recorded at the time of each baseline commit (see
  git history). They are not reproducible from the current code, and they
  differ from the "string rules only" mode of `rootiq benchmark`, which ignores
  all observed evidence.*
- *The heldout2 baseline initially showed one confident wrong answer, caused by
  a group-level diagnosis bug (failures sharing a fingerprint borrowed each
  other's evidence). It was fixed, and the baseline was re-recorded with
  per-test diagnosis.*

CI fails if any batch drops below its recorded floor or if any confident wrong
answer appears (`scripts/check_benchmark.py`).

**Native crash batch (n=1).** A C program that dereferences NULL fails on
Windows with exit code `0xC0000005`. The first baseline recorded it as a plain
`AssertionError` and diagnosed `application_defect` at 0.50, because the exit
code was not being collected. After adding a native-process evidence record
(exit code in hex, last stdout line) and a rule for NTSTATUS crash codes, it is
diagnosed as `native_memory_fault` at 0.90. With one case this is a regression
check, not an accuracy figure.

### Retrieval-only baseline (leave-one-out, n=21)

Copying the nearest neighbor's ground-truth label: **7/21 correct**, with
**7 wrong answers at similarity >= 0.70**. Similar-looking error text often
hides different causes (404, 401 and 503 all read as `HTTPError`).

### Three-way comparison (top-1 / top-3, n=21, measured before the native case)

| System | top-1 | top-3 |
|---|---|---|
| Rules + observed evidence | 20/21 | 20/21 |
| Retrieval only | 7/21 | 8/21 |
| Hybrid (rules first, retrieval as candidates) | 20/21 | 20/21 |

These are regression numbers for the rule-based systems (see above).

### LLM reasoner

An evidence-packet reasoner with strict validation exists (anonymous evidence
IDs, URL paths redacted, rejects invented IDs and uncited claims). A full
benchmark run was blocked by an API quota limit, so **no LLM accuracy figure is
claimed yet.** Early observations from a partial run, not final measurements:
the model's stated confidence was not informative, and it did not abstain on a
case with thin evidence.

## Limitations

- Small sample: 22 labeled cases, several of them near-duplicates.
- Labels overlap in places (`network_path_or_firewall` vs
  `network_path_or_service_unavailable`), and `schema_mismatch` is arguably
  `application_defect`.
- Confidence values are hand-set rule strengths, not calibrated probabilities.
- Packet evidence is loopback plus one blackhole address, captured on Windows.
- Native analysis is Windows-only so far: the rule matches NTSTATUS exit codes
  only, with no stack traces, Linux signals or core dumps.
- CI runs the benchmark regression check on a cleaned sample run. It does not
  run the network, packet-capture or native tests, which need Windows.
- History counts only runs that were analyzed (`rootiq run` now does this
  automatically; older runs were backfilled once).
- Multiple-choice LLM evaluation is easier than open-ended diagnosis.
- The API is read-only and unauthenticated: keep it on 127.0.0.1.
- Not covered yet: Docker, PostgreSQL, a larger public dataset such as RCAEval.

## Layout

```
rootiq/collector   test runner, metrics, sockets, HTTP, native, packet capture
rootiq/parser      error normalizer
rootiq/fingerprint failure signatures
rootiq/rca         rules, flaky, correlation, retrieval, LLM, benchmarks
rootiq/storage     SQLite history
rootiq/api.py      read-only REST API and dashboard
benchmark/         labeled cases and a cleaned sample run
native/            small C programs used as crash scenarios
scripts/           sample-run builder and CI regression check
tests/             demo suite with intentional faults
```