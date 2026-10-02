import json
from pathlib import Path

MIN_OBSERVATIONS = 5  # don't judge a test from fewer runs than this
RUN_STATUSES = ("passed", "failed", "error")


def load_history(runs_dir: Path = Path("runs")) -> dict[str, list[str]]:
    """test_id -> list of statuses, oldest run first (skipped tests ignored)."""
    history: dict[str, list[str]] = {}
    for p in sorted(runs_dir.glob("run_*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        for t in rec.get("tests", []):
            if t["status"] in RUN_STATUSES:
                history.setdefault(t["test_id"], []).append(t["status"])
    return history


def classify(history: dict[str, list[str]]) -> list[dict]:
    results = []
    for test_id, statuses in history.items():
        outcomes = ["pass" if s == "passed" else "fail" for s in statuses]
        n = len(outcomes)
        fails = outcomes.count("fail")
        transitions = sum(a != b for a, b in zip(outcomes, outcomes[1:]))

        if n < MIN_OBSERVATIONS:
            verdict = "insufficient_data"
        elif fails == 0:
            verdict = "stable_pass"
        elif fails == n:
            verdict = "persistent_failure"
        elif transitions >= 2:
            verdict = "flaky"
        else:
            verdict = "changed_once"  # likely a fix or a regression, not flakiness

        results.append({
            "test_id": test_id,
            "verdict": verdict,
            "runs": n,
            "failures": fails,
            "fail_rate": round(fails / n, 2),
            "transitions": transitions,
            "history": "".join("P" if o == "pass" else "F" for o in outcomes),
        })
    return results