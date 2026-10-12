import json
import time
from collections import Counter
from pathlib import Path

from rootiq.fingerprint.signatures import make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.benchmark import UNKNOWN, load_cases
from rootiq.rca.llm_reasoner import MODEL, diagnose_failure

RETRY_WAITS = [5, 15, 45, 90]  # seconds before each retry
PAUSE = 15                   # seconds between calls (free-tier rate limit)
HIGH_CONF = 0.9
RETRYABLE = ("API error 503", "API error 429", "API error 500",
             "API error 502", "API error 504")


def _path(run_id: str, include_rule: bool) -> Path:
    mode = "rule" if include_rule else "norule"
    return Path("runs") / f"llm_{run_id}_{mode}.json"


def _load_context(run_id: str):
    rec = json.loads((Path("runs") / f"{run_id}.json").read_text(encoding="utf-8"))
    evidence = rec.get("evidence", [])
    for i, e in enumerate(evidence, 1):
        e["id"] = f"EV{i}"
    flows = (rec.get("network") or {}).get("flows")
    cases = load_cases()
    fails = []
    for t in rec["tests"]:
        if t["status"] in ("failed", "error") and t["test_id"] in cases:
            f = normalize_failure(t)
            f["fingerprint"] = make_fingerprint(f)
            fails.append(f)
    return rec, evidence, flows, cases, fails


def _call_with_retry(rec, f, evidence, flows, include_rule):
    """Returns (result, None) or (None, error text). Retries temporary failures."""
    last = ""
    for wait in [0] + RETRY_WAITS:
        if wait:
            time.sleep(wait)
        try:
            return diagnose_failure(rec, f, evidence, flows, include_rule), None
        except Exception as e:
            last = str(e)
            if not (isinstance(e, OSError) or last.startswith(RETRYABLE)):
                break  # key, model or request problem: retrying will not help
    return None, last


def _record(res, err) -> dict:
    if res is None:
        return {"status": "api_failure", "error": (err or "")[:200]}
    u = res["usage"]
    base = {"model": MODEL,
            "total_tokens": u.get("totalTokenCount", 0),
            "thought_tokens": u.get("thoughtsTokenCount", 0)}
    if not res["valid"]:
        kind = "bad_json" if str(res["error"]).startswith("not valid JSON") else "schema"
        return {**base, "status": "rejected", "reject_kind": kind,
                "error": str(res["error"])[:200]}
    hyps = res["result"]["hypotheses"]
    return {**base, "status": "ok",
            "ranked": [h["root_cause"] for h in hyps],
            "confidence": hyps[0]["confidence"]}


def run_llm_benchmark(run_id, repeats=3, include_rule=False, limit=None) -> None:
    rec, evidence, flows, cases, fails = _load_context(run_id)
    path = _path(run_id, include_rule)
    results = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    # repeat-major order: a partial run still covers every case once
    todo = [(f, r) for r in range(repeats) for f in fails
            if results.get(f"{f['test_id']}|{r}", {}).get("status")
            not in ("ok", "rejected")]
    if limit:
        todo = todo[:limit]
    mode = "with rule hint" if include_rule else "NO rule hint"
    print(f"{len(fails)} labeled failures, {repeats} repeats, mode: {mode}; "
          f"{len(todo)} calls to make (model {MODEL})")

    failures_in_a_row = 0
    for n, (f, r) in enumerate(todo, 1):
        res, err = _call_with_retry(rec, f, evidence, flows, include_rule)
        out = _record(res, err)
        results[f"{f['test_id']}|{r}"] = out
        path.write_text(json.dumps(results, indent=1), encoding="utf-8")
        short = f["test_id"].split("::")[-1]
        detail = (out.get("ranked", ["-"])[0] if out["status"] == "ok"
                  else out.get("reject_kind", out.get("error", ""))[:60])
        print(f"[{n}/{len(todo)}] {short} #{r + 1}: {out['status']} {detail}")
        failures_in_a_row = failures_in_a_row + 1 if out["status"] == "api_failure" else 0
        if failures_in_a_row >= 3:
            print("3 API failures in a row, stopping. Rerun later: finished calls are kept.")
            break
        time.sleep(PAUSE)


def report(run_id: str, include_rule: bool = False) -> None:
    path = _path(run_id, include_rule)
    if not path.exists():
        print(f"{path} not found, run the benchmark first")
        return
    results = json.loads(path.read_text(encoding="utf-8"))
    cases = load_cases()
    by_test: dict[str, list[dict]] = {}
    for key, v in results.items():
        by_test.setdefault(key.rsplit("|", 1)[0], []).append(v)

    mode = "with rule hint" if include_rule else "NO rule hint"
    print(f"\nLLM benchmark on {run_id}, mode: {mode}\n")
    groups = [("all", lambda k: True), ("real", lambda k: k == "real"),
              ("simulated", lambda k: k == "simulated"),
              ("held-out", lambda k: k.startswith("heldout"))]
    for name, pick in groups:
        tests = [t for t in by_test if t in cases and pick(cases[t]["kind"])]
        calls = [v for t in tests for v in by_test[t]]
        ok = [(t, v) for t in tests for v in by_test[t] if v["status"] == "ok"]
        if not calls:
            continue
        top1 = sum(v["ranked"][0] == cases[t]["truth"] for t, v in ok)
        top3 = sum(cases[t]["truth"] in v["ranked"] for t, v in ok)
        unk = sum(v["ranked"][0] == UNKNOWN for _, v in ok)
        conf_wrong = sum(1 for t, v in ok
                         if v["ranked"][0] not in (cases[t]["truth"], UNKNOWN)
                         and v["confidence"] >= HIGH_CONF)
        maj_ok = maj_n = 0
        agree = []
        for t in tests:
            tops = [v["ranked"][0] for v in by_test[t] if v["status"] == "ok"]
            if tops:
                top, c = Counter(tops).most_common(1)[0]
                maj_n += 1
                maj_ok += top == cases[t]["truth"]
                agree.append(c / len(tops))
        rej_json = sum(v.get("reject_kind") == "bad_json" for v in calls)
        rej_schema = sum(v.get("reject_kind") == "schema" for v in calls)
        api_fail = sum(v["status"] == "api_failure" for v in calls)
        print(f"== {name} ({len(tests)} tests, {len(calls)} calls) ==")
        print(f"  per-call top-1   {top1}/{len(ok)}    top-3 {top3}/{len(ok)}")
        print(f"  majority top-1   {maj_ok}/{maj_n}    "
              f"mean agreement {sum(agree) / max(len(agree), 1):.0%}")
        print(f"  unknown answers  {unk}    confident wrong (conf >= {HIGH_CONF}): {conf_wrong}")
        print(f"  rejected         {rej_json} bad/truncated JSON, {rej_schema} schema    "
              f"api failures: {api_fail}\n")

    allv = [v for vs in by_test.values() for v in vs if v["status"] != "api_failure"]
    print(f"tokens: {sum(v['total_tokens'] for v in allv)} total, "
          f"{sum(v['thought_tokens'] for v in allv)} of them thinking")
    print("\nTests whose majority answer is wrong:")
    for t, vs in sorted(by_test.items()):
        tops = [v["ranked"][0] for v in vs if v["status"] == "ok"]
        if t in cases and tops:
            top = Counter(tops).most_common(1)[0][0]
            if top != cases[t]["truth"]:
                print(f"  {t.split('::')[-1]}: truth={cases[t]['truth']}, votes={tops}")