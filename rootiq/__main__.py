import argparse
import json
from pathlib import Path

from rootiq.collector.runner import run_tests
from rootiq.fingerprint.signatures import group_failures, make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.correlate import correlate, load_observations
from rootiq.rca.flaky import MIN_OBSERVATIONS, classify, load_history
from rootiq.rca.rules import diagnose_with_evidence
from rootiq.storage.history import history_for, save_run
from rootiq.rca.benchmark import load_cases, score, summarize


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


def cmd_analyze(run_id: str) -> None:
    path = Path("runs") / f"{run_id}.json"
    if not path.exists():
        print(f"{path} not found")
        return
    rec = json.loads(path.read_text(encoding="utf-8"))
    evidence = rec.get("evidence", [])
    flows = (rec.get("network") or {}).get("flows")
    for i, e in enumerate(evidence, 1):
        e["id"] = f"EV{i}"  # stable: position in this run's evidence list

    raw = [t for t in rec["tests"] if t["status"] in ("failed", "error")]
    failures = []
    for t in raw:
        f = normalize_failure(t)
        f["fingerprint"] = make_fingerprint(f)
        failures.append(f)

    groups = group_failures(failures)
    diagnoses = {fp: diagnose_with_evidence(items, evidence, flows)
                 for fp, items in groups.items()}

    print(f"{run_id}: {len(failures)} failure(s) in {len(groups)} group(s)")
    for fp, items in groups.items():
        d = diagnoses[fp]
        h = history_for(fp, exclude_run=run_id)
        print(f"\n[{fp}] x{len(items)}  {items[0]['error_type']}")
        print(f"  root_cause : {d['root_cause']}  (confidence {d['confidence']:.2f}, rule {d['rule_id']})")
        if d.get("string_rule_said"):
            print(f"  string rule: said {d['string_rule_said']}, overridden by observed evidence")
        if h["runs_seen"]:
            print(f"  history    : seen in {h['runs_seen']} earlier run(s) "
                  f"({h['first_seen']} to {h['last_seen']})")
        else:
            print("  history    : new failure, not seen before")
        print("  evidence   :")
        for line in d["evidence"]:
            print(f"    - {line}")
        print(f"  next_tests : {'; '.join(d['next_tests'])}")
        for t in d["affected_tests"]:
            print(f"    affects: {t}")

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
    path = Path("runs") / f"{run_id}.json"
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
        for kind in ("real", "simulated"):
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

def main() -> None:
    parser = argparse.ArgumentParser(prog="rootiq")
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="Run the pytest suite and save evidence")
    r.add_argument("--stress", action="store_true", help="Burn CPU during the run")
    a = sub.add_parser("analyze", help="Analyze a saved run")
    a.add_argument("run_id")
    sub.add_parser("flaky", help="Detect flaky tests from run history")
    sub.add_parser("correlate", help="Check whether failures line up with CPU load")
    b = sub.add_parser("benchmark", help="Score diagnoses against labeled ground truth")
    b.add_argument("run_id")
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


if __name__ == "__main__":
    main()