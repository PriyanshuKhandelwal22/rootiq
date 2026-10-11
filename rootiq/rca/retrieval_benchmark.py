from rootiq.rca.benchmark import load_cases
from rootiq.rca.retrieval import load_documents, rank_all

UNKNOWN_BELOW = 0.30  # nearest neighbor weaker than this -> "unknown"


def score_retrieval() -> list[dict]:
    cases = load_cases()
    docs = [d for d in load_documents() if d["test_id"] in cases]
    ranked = rank_all(docs)
    rows = []
    for d in docs:
        truth = cases[d["test_id"]]["truth"]
        score, nn = ranked[d["test_id"]][0]
        nn_truth = cases[nn["test_id"]]["truth"]
        pred = nn_truth if score >= UNKNOWN_BELOW else "unknown_insufficient_evidence"
        rows.append({
            "test_id": d["test_id"], "kind": cases[d["test_id"]]["kind"],
            "truth": truth, "pred": pred, "score": score,
            "neighbor": nn["test_id"], "correct": pred == truth,
        })
    return rows