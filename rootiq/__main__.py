import argparse

from rootiq.collector.runner import run_tests


def main() -> None:
    parser = argparse.ArgumentParser(prog="rootiq")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Run the pytest suite and save evidence")
    args = parser.parse_args()

    if args.command == "run":
        rec = run_tests()
        print(f"{rec['run_id']} saved to runs\\{rec['run_id']}.json")
        print(f"exit_code={rec['exit_code']}  duration={rec['duration_sec']}s")


if __name__ == "__main__":
    main()