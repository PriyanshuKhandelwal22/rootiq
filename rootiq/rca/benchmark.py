import json
from pathlib import Path

from rootiq.fingerprint.signatures import group_failures, make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.rules import diagnose, diagnose_with_evidence

CASES_PATH = Path("benchmark") / "cases.json"
UNKNOWN = "unknown_insufficient_evidence"
HIGH_CONF = 0.70


def load_cases() -> dict:
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def diagnose_run(rec: dict, use_evidence: bool) -> dict[str, dict]:
    """test_id -> diagnosis, for every failed test in one run record."""
    evidence = rec.get("evidence", [])
    for i, e in enumerate(evidence, 1):
        e["id"] = f"EV{i}"  # same IDs that analyze assigns
    flows = (rec.get("network") or {}).get("flows")

    failures = []
    for t in rec["tests"]:
        if t["status"] in ("failed", "error"):
            f = normalize_failure(t)
            f["fingerprint"] = make_fingerprint(f)
            failures.append(f)

    out = {}
    for items in group_failures(failures).values():
        d = (diagnose_with_evidence(items, evidence, flows)
             if use_evidence else diagnose(items))
        for f in items:
            out[f["test_id"]] = d
    return out


def score(rec: dict, cases: dict, use_evidence: bool) -> list[dict]:
    diags = diagnose_run(rec, use_evidence)
    rows = []
    for test_id, case in cases.items():
        d = diags.get(test_id)
        if d is None:
            continue  # did not fail in this run, so nothing to diagnose
        rows.append({
            "test_id": test_id,
            "kind": case["kind"],
            "truth": case["truth"],
            "pred": d["root_cause"],
            "confidence": d["confidence"],
            "correct": d["root_cause"] == case["truth"],
        })
    return rows


def summarize(rows: list[dict]) -> dict:
    wrong_high = [r for r in rows
                  if not r["correct"] and r["pred"] != UNKNOWN
                  and r["confidence"] >= HIGH_CONF]
    return {
        "n": len(rows),
        "correct": sum(r["correct"] for r in rows),
        "unknown": sum(r["pred"] == UNKNOWN for r in rows),
        "wrong_high_conf": len(wrong_high),
    }