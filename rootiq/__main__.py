import argparse
import json
from pathlib import Path

from rootiq.collector.runner import run_tests
from rootiq.parser.normalizer import normalize_failure


def cmd_run() -> None:
    rec = run_tests()
    s = rec["summary"]
    print(f"{rec['run_id']} saved to runs\\{rec['run_id']}.json")
    print(f"exit_code={rec['exit_code']}  duration={rec['duration_sec']}s")
    print(f"{s['passed']} passed, {s['failed']} failed, "
          f"{s['error']} errors, {s['skipped']} skipped")
    for t in rec["tests"]:
        if t["status"] != "passed":
            print(f"  [{t['status'].upper()}] {t['name']}: {t['message']}")


def cmd_analyze(run_id: str) -> None:
    path = Path("runs") / f"{run_id}.json"
    if not path.exists():
        print(f"{path} not found")
        return
    rec = json.loads(path.read_text(encoding="utf-8"))
    failures = [t for t in rec["tests"] if t["status"] in ("failed", "error")]
    print(f"{run_id}: {len(failures)} failure(s)")
    for t in failures:
        f = normalize_failure(t)
        frame = f["top_frame"]
        print(f"\n{f['test_id']}")
        print(f"  error_type : {f['error_type']}")
        print(f"  template   : {f['template']}")
        print(f"  top_frame  : {frame['file']}:{frame['line']}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="rootiq")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Run the pytest suite and save evidence")
    a = sub.add_parser("analyze", help="Analyze a saved run")
    a.add_argument("run_id")
    args = parser.parse_args()

    if args.command == "run":
        cmd_run()
    elif args.command == "analyze":
        cmd_analyze(args.run_id)


if __name__ == "__main__":
    main()