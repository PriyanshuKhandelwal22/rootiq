import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from rootiq.collector.junit import parse_junit
from rootiq.collector.metrics import MetricsSampler
from rootiq.collector.netprobe import read_evidence
from rootiq.collector.stress import CpuStress

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


def run_tests(pytest_args: list[str] | None = None, stress: bool = False) -> dict:
    run_id = next_run_id()
    junit_path = RUNS_DIR / f"{run_id}.junit.xml"
    evidence_path = RUNS_DIR / f"{run_id}.evidence.jsonl"
    env = {**os.environ, "ROOTIQ_EVIDENCE_FILE": str(evidence_path)}
    cmd = [sys.executable, "-m", "pytest", f"--junitxml={junit_path}",
           *(pytest_args or [])]

    sampler = MetricsSampler()
    stressor = CpuStress() if stress else None
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        if stressor:
            stressor.start()
            time.sleep(0.5)  # let the load ramp up before measuring
        sampler.start()
        start = time.perf_counter()
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8",
            errors="replace", env=env
        )
        duration = time.perf_counter() - start
        metrics = sampler.stop()
    finally:
        if stressor:
            stressor.stop()

    tests = parse_junit(junit_path)
    evidence = read_evidence(evidence_path)
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
        "stress": stress,
        "summary": summary,
        "metrics": metrics,
        "tests": tests,
        "evidence": evidence,
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