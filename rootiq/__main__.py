import argparse
import json
from operator import sub
from pathlib import Path

from rootiq.collector.runner import run_tests
from rootiq.fingerprint.signatures import group_failures, make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.correlate import correlate, load_observations
from rootiq.rca.flaky import MIN_OBSERVATIONS, classify, load_history
from rootiq.rca.rules import diagnose_with_evidence
from rootiq.storage.history import history_for, save_run
from rootiq.rca.benchmark import load_cases, score, summarize
from rootiq.rca.retrieval import find_similar
from rootiq.rca.retrieval_benchmark import score_retrieval
from rootiq.rca.hybrid import score_systems

def cmd_run(stress: bool = False) -> None:
    rec = run_tests(stress=stress)
    s = rec["summary"]
    print(f"{rec['run_id']} saved to runs\\{rec['run_id']}.json")
    print(f"exit_code={rec['exit_code']}  duration={rec['duration_sec']}s")
    print(f"{s['passed']} passed, {s['failed']} failed, "
          f"{s['error']} errors, {s['skipped']} skipped")
    m = rec["metrics"]
    print(f"cpu avg/max = {m['cpu_avg']}%/{m['cpu_max']}%   "
          f"mem avg/max = {m['mem_avg']}%/{m['mem_max']}%   "
          f"({m['sample_count']} samples)")
    print(f"stress={'ON' if rec['stress'] else 'off'}")
    n = rec.get("network") or {}
    if n.get("error"):
        print(f"capture: FAILED ({n['error']})")
    else:
        print(f"capture: {n.get('packet_count', 0)} packets -> {n.get('pcap_file')}")
    for t in rec["tests"]:
        if t["status"] != "passed":
            print(f"  [{t['status'].upper()}] {t['name']}: {t['message']}") 
    from rootiq.service import analyze_and_store
    stored = analyze_and_store(rec["run_id"])
    print(f"history: stored {stored} failure(s) for {rec['run_id']}")


def cmd_analyze(run_id: str) -> None:
    path = Path("runs") / f"{run_id}.json"
    if not path.exists():
        print(f"{path} not found")
        return
    rec = json.loads(path.read_text(encoding="utf-8"))
    evidence = rec.get("evidence", [])
    for i, e in enumerate(evidence, 1):
        e["id"] = f"EV{i}"
    flows = (rec.get("network") or {}).get("flows")

    raw = [t for t in rec["tests"] if t["status"] in ("failed", "error")]
    failures = []
    for t in raw:
        f = normalize_failure(t)
        f["fingerprint"] = make_fingerprint(f)
        failures.append(f)

    groups = group_failures(failures)
    diagnoses = {f["test_id"]: diagnose_with_evidence([f], evidence, flows)
                 for f in failures}

    print(f"{run_id}: {len(failures)} failure(s) in {len(groups)} group(s)")
    for fp, items in groups.items():
        h = history_for(fp, exclude_run=run_id)
        print(f"\n[{fp}] x{len(items)}  {items[0]['error_type']}")
        if h["runs_seen"]:
            print(f"  history    : seen in {h['runs_seen']} earlier run(s) "
                  f"({h['first_seen']} to {h['last_seen']})")
        else:
            print("  history    : new failure, not seen before")
        for f in items:
            d = diagnoses[f["test_id"]]
            print(f"  - {f['test_id']}")
            print(f"      root_cause : {d['root_cause']}  "
                  f"(confidence {d['confidence']:.2f}, rule {d['rule_id']})")
            if d.get("string_rule_said"):
                print(f"      string rule: said {d['string_rule_said']}, "
                      f"overridden by observed evidence")
            for line in d["evidence"][3:]:  # skip the generic E1-E3 lines
                print(f"      evidence   : {line}")
            print(f"      next_tests : {'; '.join(d['next_tests'])}")

    save_run(rec, failures, diagnoses)


def cmd_flaky() -> None:
    results = classify(load_history())
    n_runs = max((r["runs"] for r in results), default=0)
    print(f"Flaky-test report ({n_runs} run(s) of history, "
          f"minimum {MIN_OBSERVATIONS} observations per test)\n")
    order = {"flaky": 0, "changed_once": 1, "persistent_failure": 2,
             "insufficient_data": 3, "stable_pass": 4}
    for r in sorted(results, key=lambda r: (order[r["verdict"]], r["test_id"])):
        if r["verdict"] == "stable_pass":
            continue
        print(f"{r['verdict'].upper():<19} {r['test_id']}")
        print(f"  {r['runs']} runs, {r['failures']} failed ({r['fail_rate']:.0%}), "
              f"{r['transitions']} transitions")
        print(f"  history (oldest to newest): {r['history']}")
    stable = sum(r["verdict"] == "stable_pass" for r in results)
    print(f"\n{stable} test(s) stable_pass (not shown)")


def cmd_correlate() -> None:
    obs, run_cpu = load_observations()
    calm = [c for s, c in run_cpu if not s]
    loaded = [c for s, c in run_cpu if s]
    print(f"Runs with metrics: {len(calm)} calm, {len(loaded)} under stress")
    if calm and loaded:
        print(f"Mean CPU: calm {sum(calm)/len(calm):.1f}%  vs  "
              f"stress {sum(loaded)/len(loaded):.1f}%")
    results = correlate(obs)
    if not results:
        print("\nNo test has enough mixed-outcome data yet "
              "(need 5+ calm and 5+ stress runs).")
        return
    for r in results:
        print(f"\n{r['verdict'].upper():<15} {r['test_id']}")
        print(f"  calm  : {r['calm_fail_rate']:.0%} failed over {r['calm_runs']} runs")
        print(f"  stress: {r['loaded_fail_rate']:.0%} failed over {r['loaded_runs']} runs")

def cmd_benchmark(run_id: str) -> None:
    path = (Path("benchmark") / "sample_run.json" if run_id == "sample"
            else Path("runs") / f"{run_id}.json")  
    if not path.exists():
        print(f"{path} not found")
        return
    cases = load_cases()
    print(f"Benchmark on {run_id} ({len(cases)} labeled cases)\n")
    for name, use_ev in (("string rules only", False),
                         ("rules + observed evidence", True)):
        rec = json.loads(path.read_text(encoding="utf-8"))
        rows = score(rec, cases, use_ev)
        print(f"== {name} ==")
        for kind in ("real", "simulated", "heldout", "heldout2", "heldout3", "heldout4"):
            sub = [r for r in rows if r["kind"] == kind]
            if not sub:
                print(f"  {kind:<10} no cases failed in this run")
                continue
            s = summarize(sub)
            print(f"  {kind:<10} {s['correct']}/{s['n']} correct, "
                  f"{s['unknown']} unknown, "
                  f"{s['wrong_high_conf']} wrong at conf >= 0.70")
        for r in rows:
            if not r["correct"]:
                print(f"    MISS {r['test_id']}: truth={r['truth']}, "
                      f"got={r['pred']} ({r['confidence']:.2f})")
        print()

def cmd_similar(query: str, k: int) -> None:
    me, hits = find_similar(query, k)
    if me is None:
        print("no stored failure matches '{query}' (run analyze on a run first)")
        return
    if isinstance(me, list):
        print(f"'{query}' is ambiguous, matches:")
        for d in me:
            print(f"  {d['test_id']}")
        return
    print(f"{me['test_id']}  [{me['run_id']}]")
    print(f"  text: {me['error_type']} {me['template']}")
    print(f"  diagnosed as: {me['root_cause']}\n")
    print(f"Most similar past failures (top {k}):")
    for score, d in hits:
        print(f"  {score:.2f}  {d['test_id']}")
        print(f"        {d['template']}")
        print(f"        diagnosed as: {d['root_cause']}")

def cmd_benchmark_retrieval() -> None:
    rows = score_retrieval()
    print(f"Retrieval-only (leave-one-out) on {len(rows)} labeled failures\n")
    for kind in ("real", "simulated", "heldout", "heldout2", "heldout3"):
        sub = [r for r in rows if r["kind"] == kind]
        if not sub:
            continue
        ok = sum(r["correct"] for r in sub)
        unk = sum(r["pred"] == "unknown_insufficient_evidence" for r in sub)
        wrong_hi = sum(1 for r in sub if not r["correct"]
                       and r["pred"] != "unknown_insufficient_evidence"
                       and r["score"] >= 0.70)
        print(f"  {kind:<10} {ok}/{len(sub)} correct, {unk} unknown, "
              f"{wrong_hi} wrong at similarity >= 0.70")
    total = sum(r["correct"] for r in rows)
    print(f"\n  overall    {total}/{len(rows)} correct")
    for r in rows:
        if not r["correct"]:
            print(f"    MISS {r['test_id']}: truth={r['truth']}, got={r['pred']} "
                  f"(sim {r['score']:.2f} to {r['neighbor'].split('::')[-1]})")

def cmd_benchmark_hybrid(run_id: str) -> None:
    rows = score_systems(run_id)
    print(f"Three-way comparison on {run_id} ({len(rows)} labeled failures)\n")
    print(f"  {'':<22}{'rules+evidence':>16}{'retrieval-only':>16}{'hybrid':>10}")

    def line(label, sub):
        def hit(key, n):
            return sum(r["truth"] in r[key][:n] for r in sub)
        n = len(sub)
        for top in (1, 3):
            print(f"  {label + ' top-' + str(top):<22}"
                  f"{hit('rules', top):>13}/{n}"
                  f"{hit('retrieval', top):>13}/{n}"
                  f"{hit('hybrid', top):>7}/{n}")

    line("all", rows)
    line("held-out batches", [r for r in rows if r["kind"].startswith("heldout")])
    print()
    for r in rows:
        if r["truth"] not in r["hybrid"]:
            print(f"  MISS {r['test_id'].split('::')[-1]}: truth={r['truth']}, "
                  f"hybrid={r['hybrid'] or 'unknown'}")


def cmd_llm(run_id: str, query: str, show: bool, no_rule: bool) -> None:
    from rootiq.rca.llm_reasoner import MODEL, run_llm
    try:
        r = run_llm(run_id, query, include_rule=not no_rule)
    except Exception as e:
        print(f"failed: {e}")
        return
    if "fatal" in r:
        print(r["fatal"])
        return
    print(f"model: {MODEL}   tokens: {r['usage']}")
    if show:
        print(json.dumps(r["packet"], indent=1))
    if not r["valid"]:
        print(f"\nREJECTED by validator: {r['error']}\nraw output:\n{r['raw']}")
        return
    for i, h in enumerate(r["result"]["hypotheses"], 1):
        print(f"\n#{i} {h['root_cause']}  (confidence {h['confidence']})")
        print(f"   cites     : {', '.join(h['evidence_ids']) or '-'}")
        print(f"   observed  : {h['observed']}")
        print(f"   inference : {h['inference']}")
    print(f"\nnext_tests: {'; '.join(r['result']['next_tests'])}")

def cmd_benchmark_llm(run_id: str, repeats: int, with_rule: bool,
                      limit: int | None, score_only: bool) -> None:
    from rootiq.rca.llm_benchmark import report, run_llm_benchmark
    if not score_only:
        run_llm_benchmark(run_id, repeats, with_rule, limit)
    report(run_id, with_rule)

def main() -> None:
    parser = argparse.ArgumentParser(prog="rootiq")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="Run the pytest suite and save evidence")
    r.add_argument("--stress", action="store_true", help="Burn CPU during the run")
    a = sub.add_parser("analyze", help="Analyze a saved run")
    a.add_argument("run_id")
    sub.add_parser("flaky", help="Detect flaky tests from run history")
    sub.add_parser("correlate", help="Check whether failures line up with CPU load")
    sub.add_parser("benchmark-retrieval", help="Score retrieval-only diagnosis")
    s = sub.add_parser("similar", help="Find past failures similar to one test")
    s.add_argument("query")
    s.add_argument("-k", type=int, default=3)
    b = sub.add_parser("benchmark", help="Score diagnoses against labeled ground truth")
    b.add_argument("run_id")
    h = sub.add_parser("benchmark-hybrid", help="Compare rules, retrieval and hybrid")
    h.add_argument("run_id")
    l = sub.add_parser("llm", help="LLM diagnosis of one failure")
    l.add_argument("run_id")
    l.add_argument("query")
    l.add_argument("--show-packet", action="store_true")
    l.add_argument("--no-rule", action="store_true",
                   help="hide the rule engine's answer from the model")
    q = sub.add_parser("benchmark-llm", help="Score the LLM reasoner on labeled failures")
    q.add_argument("run_id")
    q.add_argument("--repeats", type=int, default=3)
    q.add_argument("--with-rule", action="store_true",
                   help="show the rule engine's answer to the model (default: hidden)")
    q.add_argument("--limit", type=int, default=None,
                   help="make at most this many new calls, for batching")
    q.add_argument("--score-only", action="store_true")
    args = parser.parse_args()

    if args.command == "run":
        cmd_run(args.stress)
    elif args.command == "analyze":
        cmd_analyze(args.run_id)
    elif args.command == "flaky":
        cmd_flaky()
    elif args.command == "correlate":
        cmd_correlate()
    elif args.command == "benchmark":
        cmd_benchmark(args.run_id)
    elif args.command == "similar":
        cmd_similar(args.query, args.k)
    elif args.command == "benchmark-retrieval":
        cmd_benchmark_retrieval()
    elif args.command == "benchmark-hybrid":
        cmd_benchmark_hybrid(args.run_id)
    elif args.command == "llm":
        cmd_llm(args.run_id, args.query, args.show_packet, args.no_rule)
    elif args.command == "benchmark-llm":
        cmd_benchmark_llm(args.run_id, args.repeats, args.with_rule,
                          args.limit, args.score_only)

if __name__ == "__main__":
    main()