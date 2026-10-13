import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from rootiq.fingerprint.signatures import make_fingerprint
from rootiq.parser.normalizer import normalize_failure
from rootiq.rca.benchmark import UNKNOWN, load_cases
from rootiq.rca.retrieval import load_documents, rank_all
from rootiq.rca.rules import _describe, diagnose_with_evidence, packet_check

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
MODEL = os.environ.get("ROOTIQ_MODEL", "gemini-2.5-flash")

SYSTEM = """You are a software failure-diagnosis engine.
Use only the supplied evidence. Do not invent observations.
Every hypothesis other than "unknown_insufficient_evidence" must cite evidence ids from the packet.
Keep what was observed separate from what you infer.
If the evidence does not support a diagnosis, answer "unknown_insufficient_evidence".
Return ONLY a JSON object, no markdown, in this shape:
{"hypotheses": [{"root_cause": <one of allowed_root_causes, or "other">,
  "other_description": <string or null>, "confidence": <number 0 to 1>,
  "evidence_ids": [<ids from the packet>], "observed": <string>, "inference": <string>}],
 "next_tests": [<string>]}
Rank hypotheses best first. At most 3."""


def allowed_root_causes() -> list[str]:
    return sorted({c["truth"] for c in load_cases().values()}) + [UNKNOWN]


def _redact(e: dict) -> dict:
    """Hide URL paths: they can contain the answer (for example /missing)."""
    e = dict(e)
    if e.get("url"):
        p = urlparse(e["url"])
        e["url"] = f"{p.scheme}://{p.netloc}/<path>"
    return e


def _neighbors(test_id: str, k: int = 3, min_sim: float = 0.30) -> list[dict]:
    ranked = rank_all(load_documents())
    return [{"similarity": round(s, 2), "error_text": d["template"],
             "past_diagnosis": d["root_cause"]}
            for s, d in ranked.get(test_id, []) if s >= min_sim][:k]


def build_packet(rec, f, evidence, flows, rule, neighbors, include_rule=True):
    """Anonymous evidence packet: no test names, only ids the model can cite."""
    items = [{"id": "MSG", "kind": "error_message", "text": f["raw_message"][:300]},
             {"id": "ERRTYPE", "kind": "error_type", "text": f["error_type"]}]
    for e in evidence:
        if e.get("test_id") != f["test_id"]:
            continue
        items.append({"id": e["id"], "kind": e["type"], "text": _describe(_redact(e))})
        if e["type"] == "socket" and flows is not None:
            c = packet_check(e, flows)
            if c["status"] != "n/a":
                items.append({"id": f"PKT-{e['id']}", "kind": "packet_check",
                              "text": f"{c['status']}: {c['note']}"})
    m = rec.get("metrics")
    if m:
        items.append({"id": "METRICS", "kind": "system_metrics",
                      "text": f"cpu avg {m['cpu_avg']}% max {m['cpu_max']}%, "
                              f"mem avg {m['mem_avg']}%"})
    packet = {"allowed_root_causes": allowed_root_causes(),
              "error_type": f["error_type"], "evidence": items,
              "similar_past_failures": neighbors}
    if include_rule and rule["root_cause"] != UNKNOWN:
        packet["rule_engine_suggestion"] = {"root_cause": rule["root_cause"],
                                            "confidence": rule["confidence"]}
    return packet, {i["id"] for i in items}


def call_model(user_text: str, max_tokens: int = 8000):
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        raise RuntimeError("GEMINI_API_KEY is not set")
    payload = {
        "systemInstruction": {"parts": [{"text": SYSTEM}]},
        "contents": [{"role": "user", "parts": [{"text": user_text}]}],
        "generationConfig": {
            "maxOutputTokens": max_tokens,
            "responseMimeType": "application/json",
            "thinkingConfig": {"thinkingBudget": 1024},
        },
    }
    req = urllib.request.Request(
        API_URL.format(model=MODEL), data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", "x-goog-api-key": key})
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"API error {e.code}: {e.read().decode()[:1500]}")
    try:
        parts = data["candidates"][0]["content"]["parts"]
    except (KeyError, IndexError):
        raise RuntimeError(f"no answer returned (blocked or empty): {str(data)[:1500]}")
    text = "".join(p.get("text", "") for p in parts)
    return text, data.get("usageMetadata", {})

def validate(text: str, valid_ids: set[str]):
    t = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        obj = json.loads(t)
    except json.JSONDecodeError as e:
        return False, f"not valid JSON: {e}"
    hyps = obj.get("hypotheses")
    if not isinstance(hyps, list) or not 1 <= len(hyps) <= 3:
        return False, "hypotheses must be a list of 1 to 3"
    allowed = set(allowed_root_causes()) | {"other"}
    for h in hyps:
        if h.get("root_cause") not in allowed:
            return False, f"root_cause not allowed: {h.get('root_cause')}"
        c = h.get("confidence")
        if not isinstance(c, (int, float)) or not 0 <= c <= 1:
            return False, "confidence must be a number 0..1"
        ids = h.get("evidence_ids")
        if not isinstance(ids, list):
            return False, "evidence_ids must be a list"
        bad = [i for i in ids if i not in valid_ids]
        if bad:
            return False, f"cites evidence ids not in the packet: {bad}"
        if h["root_cause"] != UNKNOWN and not ids:
            return False, "non-unknown hypothesis cites no evidence"
    return True, obj


def diagnose_failure(rec, f, evidence, flows, include_rule=True):
    rule = diagnose_with_evidence([f], evidence, flows)
    packet, valid_ids = build_packet(rec, f, evidence, flows, rule,
                                     _neighbors(f["test_id"]), include_rule)
    text, usage = call_model(json.dumps(packet, indent=1))
    ok, parsed = validate(text, valid_ids)
    return {"packet": packet, "raw": text, "valid": ok,
            "result": parsed if ok else None,
            "error": None if ok else parsed, "usage": usage}


def run_llm(run_id: str, query: str, include_rule: bool = True) -> dict:
    rec = json.loads((Path("runs") / f"{run_id}.json").read_text(encoding="utf-8"))
    evidence = rec.get("evidence", [])
    for i, e in enumerate(evidence, 1):
        e["id"] = f"EV{i}"
    flows = (rec.get("network") or {}).get("flows")
    fails = []
    for t in rec["tests"]:
        if t["status"] in ("failed", "error") and query in t["test_id"]:
            f = normalize_failure(t)
            f["fingerprint"] = make_fingerprint(f)
            fails.append(f)
    if len(fails) != 1:
        return {"fatal": f"'{query}' matched {len(fails)} failures, need exactly 1"}
    return diagnose_failure(rec, fails[0], evidence, flows, include_rule)