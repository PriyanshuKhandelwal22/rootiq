import json
from pathlib import Path

from rootiq.rca.benchmark import UNKNOWN, diagnose_run, load_cases
from rootiq.rca.retrieval import load_documents, rank_all

MIN_SIM = 0.30


def _neighbor_labels(ranked: list, cases: dict, k: int = 3) -> list[str]:
    """Distinct ground-truth labels of the nearest neighbors above MIN_SIM."""
    out = []
    for score, nn in ranked:  # already sorted, best first
        if score < MIN_SIM:
            break
        label = cases[nn["test_id"]]["truth"]
        if label not in out:
            out.append(label)
        if len(out) == k:
            break
    return out


def score_systems(run_id: str) -> list[dict]:
    rec = json.loads((Path("runs") / f"{run_id}.json").read_text(encoding="utf-8"))
    cases = load_cases()
    docs = [d for d in load_documents() if d["test_id"] in cases]
    ranked = rank_all(docs)
    diags = diagnose_run(rec, use_evidence=True)

    rows = []
    for d in docs:
        tid = d["test_id"]
        if tid not in diags:
            continue  # did not fail in this run
        truth = cases[tid]["truth"]
        rule = diags[tid]["root_cause"]
        nb = _neighbor_labels(ranked[tid], cases)
        rule_list = [] if rule == UNKNOWN else [rule]
        hybrid = (rule_list + [x for x in nb if x != rule])[:3]
        rows.append({
            "test_id": tid, "kind": cases[tid]["kind"], "truth": truth,
            "rules": rule_list, "retrieval": nb, "hybrid": hybrid,
        })
    return rows