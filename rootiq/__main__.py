import argparse
import json
from pathlib import Path

from rootiq.collector.runner import run_tests
from rootiq.fingerprint.signatures import group_failures, make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.flaky import MIN_OBSERVATIONS, classify, load_history
from rootiq.rca.rules import diagnose
from rootiq.storage.history import history_for, save_run


def cmd_run() -> None:
    rec = run_tests()
    s = rec["summary"]
    print(f"{rec['run_id']} saved to runs\\{rec['run_id']}.json")
    print(f"exit_code={rec['exit_code']}  duration={rec['duration_sec']}s")
    print(f"{s['passed']} passed, {s['failed']} failed, "
          f"{s['error']} errors, {s['skipped']} skipped")
    m = rec["metrics"]
    print(f"cpu avg/max = {m['cpu_avg']}%/{m['cpu_max']}%   "
          f"mem avg/max = {m['mem_avg']}%/{m['mem_max']}%   "
          f"({m['sample_count']} samples)")
    for t in rec["tests"]:
        if t["status"] != "passed":
            print(f"  [{t['status'].upper()}] {t['name']}: {t['message']}")


def cmd_analyze(run_id: str) -> None:
    path = Path("runs") / f"{run_id}.json"
    if not path.exists():
        print(f"{path} not found")
        return
    rec = json.loads(path.read_text(encoding="utf-8"))
    raw = [t for t in rec["tests"] if t["status"] in ("failed", "error")]

    failures = []
    for t in raw:
        f = normalize_failure(t)
        f["fingerprint"] = make_fingerprint(f)
        failures.append(f)

    groups = group_failures(failures)
    diagnoses = {fp: diagnose(items) for fp, items in groups.items()}

    print(f"{run_id}: {len(failures)} failure(s) in {len(groups)} group(s)")
    for fp, items in groups.items():
        d = diagnoses[fp]
        h = history_for(fp, exclude_run=run_id)
        print(f"\n[{fp}] x{len(items)}  {items[0]['error_type']}")
        print(f"  root_cause : {d['root_cause']}  (confidence {d['confidence']:.2f}, rule {d['rule_id']})")
        if h["runs_seen"]:
            print(f"  history    : seen in {h['runs_seen']} earlier run(s) "
                  f"({h['first_seen']} to {h['last_seen']})")
        else:
            print("  history    : new failure, not seen before")
        print(f"  next_tests : {'; '.join(d['next_tests'])}")
        for t in d["affected_tests"]:
            print(f"    - {t}")

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


def main() -> None:
    parser = argparse.ArgumentParser(prog="rootiq")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Run the pytest suite and save evidence")
    a = sub.add_parser("analyze", help="Analyze a saved run")
    a.add_argument("run_id")
    sub.add_parser("flaky", help="Detect flaky tests from run history")
    args = parser.parse_args()

    if args.command == "run":
        cmd_run()
    elif args.command == "analyze":
        cmd_analyze(args.run_id)
    elif args.command == "flaky":
        cmd_flaky()


if __name__ == "__main__":
    main()