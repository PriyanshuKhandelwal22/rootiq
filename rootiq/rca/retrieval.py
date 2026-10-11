import math
import re
from collections import Counter

from rootiq.storage.history import connect

TOKEN_RE = re.compile(r"[a-z]+")


def tokens(text: str) -> list[str]:
    return TOKEN_RE.findall(text.lower())


def load_documents() -> list[dict]:
    """The most recent stored failure for each test."""
    with connect() as conn:
        rows = conn.execute(
            "SELECT test_id, run_id, error_type, template, root_cause, confidence "
            "FROM failures WHERE id IN (SELECT MAX(id) FROM failures GROUP BY test_id)"
        ).fetchall()
    return [{"test_id": r[0], "run_id": r[1], "error_type": r[2], "template": r[3],
             "root_cause": r[4], "confidence": r[5], "text": f"{r[2]} {r[3]}"}
            for r in rows]


def _vector(toks: list[str], idf: dict[str, float]) -> dict[str, float]:
    v = {w: c * idf[w] for w, c in Counter(toks).items() if w in idf}
    norm = math.sqrt(sum(x * x for x in v.values())) or 1.0
    return {w: x / norm for w, x in v.items()}


def _cosine(a: dict, b: dict) -> float:
    if len(a) > len(b):
        a, b = b, a
    return sum(x * b.get(w, 0.0) for w, x in a.items())


def find_similar(query: str, k: int = 3):
    """Returns (matched_doc, [(score, doc), ...]) or (None, []) if nothing matches."""
    docs = load_documents()
    matches = [d for d in docs if query in d["test_id"]]
    if len(matches) != 1:
        return (matches or None), []
    me = matches[0]

    all_tokens = [tokens(d["text"]) for d in docs]
    df = Counter()
    for t in all_tokens:
        df.update(set(t))
    n = len(docs)
    idf = {w: math.log((1 + n) / (1 + c)) + 1 for w, c in df.items()}

    my_vec = _vector(tokens(me["text"]), idf)
    scored = [(_cosine(my_vec, _vector(t, idf)), d)
              for t, d in zip(all_tokens, docs) if d["test_id"] != me["test_id"]]
    scored.sort(key=lambda x: -x[0])
    return me, scored[:k]