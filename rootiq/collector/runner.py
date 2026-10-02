import json
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

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
    cmd = [sys.executable, "-m", "pytest", *(pytest_args or [])]

    started_at = datetime.now(timezone.utc).isoformat()
    start = time.perf_counter()
    proc = subprocess.run(
        cmd, capture_output=True, text=True, encoding="utf-8", errors="replace"
    )
    duration = time.perf_counter() - start

    record = {
        "run_id": run_id,
        "timestamp": started_at,
        "command": cmd,
        "exit_code": proc.returncode,
        "duration_sec": round(duration, 3),
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