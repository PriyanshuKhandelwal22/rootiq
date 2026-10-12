import json
from pathlib import Path

from rootiq.fingerprint.signatures import make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.flaky import classify, load_history
from rootiq.rca.rules import diagnose_with_evidence
from rootiq.storage.history import history_for

RUNS = Path("runs")


def list_runs() -> list[dict]:
    out = []
    for p in sorted(RUNS.glob("run_*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        out.append({"run_id": rec["run_id"], "timestamp": rec["timestamp"],
                    "exit_code": rec["exit_code"], "summary": rec.get("summary")})
    return out


def analyze_run(run_id: str) -> dict | None:
    path = RUNS / f"{run_id}.json"
    if not path.exists():
        return None
    rec = json.loads(path.read_text(encoding="utf-8"))
    evidence = rec.get("evidence", [])
    for i, e in enumerate(evidence, 1):
        e["id"] = f"EV{i}"
    flows = (rec.get("network") or {}).get("flows")

    failures = []
    for t in rec["tests"]:
        if t["status"] in ("failed", "error"):
            f = normalize_failure(t)
            f["fingerprint"] = make_fingerprint(f)
            d = diagnose_with_evidence([f], evidence, flows)
            h = history_for(f["fingerprint"], exclude_run=run_id)
            failures.append({
                "test_id": f["test_id"], "fingerprint": f["fingerprint"],
                "error_type": f["error_type"],
                "root_cause": d["root_cause"], "confidence": d["confidence"],
                "rule_id": d["rule_id"], "evidence": d["evidence"][3:],
                "alternatives": d["alternatives"], "next_tests": d["next_tests"],
                "history": h,
            })
    return {"run_id": run_id, "summary": rec.get("summary"),
            "failures": failures}


def flaky_report() -> list[dict]:
    return [r for r in classify(load_history()) if r["verdict"] != "stable_pass"]