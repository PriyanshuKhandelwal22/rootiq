import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rootiq.collector.junit import parse_junit
from rootiq.collector.metrics import MetricsSampler

RUNS_DIR = Path("runs")


def next_run_id() -> str:
    RUNS_DIR.mkdir(exist_ok=True)
    numbers = []
    for p in RUNS_DIR.glob("run_*.json"):
        try:
            numbers.append(int(p.stem.split("_")[1]))
        except (IndexError, ValueError):
            pass
    return f"run_{(max(numbers, default=0) + 1):03d}"


def run_tests(pytest_args: list[str] | None = None) -> dict:
    run_id = next_run_id()
    junit_path = RUNS_DIR / f"{run_id}.junit.xml"
    cmd = [sys.executable, "-m", "pytest", f"--junitxml={junit_path}",
           *(pytest_args or [])]

    sampler = MetricsSampler()
    started_at = datetime.now(timezone.utc).isoformat()
    sampler.start()
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    duration = time.perf_counter() - start
    metrics = sampler.stop()

    tests = parse_junit(junit_path)
    summary = {
        "total": len(tests),
        "passed": sum(t["status"] == "passed" for t in tests),
        "failed": sum(t["status"] == "failed" for t in tests),
        "error": sum(t["status"] == "error" for t in tests),
        "skipped": sum(t["status"] == "skipped" for t in tests),
    }

    record = {
        "run_id": run_id,
        "timestamp": started_at,
        "command": cmd,
        "exit_code": proc.returncode,
        "duration_sec": round(duration, 3),
        "summary": summary,
        "metrics": metrics,
        "tests": tests,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "environment": {
            "python": platform.python_version(),
            "os": platform.platform(),
            "machine": platform.machine(),
        },
    }

    (RUNS_DIR / f"{run_id}.json").write_text(
        json.dumps(record, indent=2), encoding="utf-8"
    )
    return record