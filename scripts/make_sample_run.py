import json
import sys
from pathlib import Path

src = Path("runs") / f"{sys.argv[1]}.json"
rec = json.loads(src.read_text(encoding="utf-8"))

sample = {
    "run_id": "sample",
    "timestamp": "2026-01-01T00:00:00+00:00",
    "exit_code": rec["exit_code"],
    "summary": rec["summary"],
    "tests": [{k: t[k] for k in ("test_id", "suite", "name", "status",
                                 "message", "traceback")}
              for t in rec["tests"]],
    "evidence": [{k: v for k, v in e.items() if k not in ("ts",)}
                 for e in rec.get("evidence", [])],
    "network": {"flows": (rec.get("network") or {}).get("flows")},
    "metrics": {"cpu_avg": 0, "cpu_max": 0, "mem_avg": 0, "mem_max": 0},
}
out = Path("benchmark") / "sample_run.json"
out.write_text(json.dumps(sample, indent=1), encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size // 1024} KB)")