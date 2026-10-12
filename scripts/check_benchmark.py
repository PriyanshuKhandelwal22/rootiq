import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import json
from pathlib import Path

from rootiq.rca.benchmark import load_cases, score

# minimum correct per batch for rules + observed evidence (regression floor)
FLOOR = {"real": 3, "simulated": 7, "heldout": 3, "heldout2": 3, "heldout3": 4}

rec = json.loads(Path("benchmark/sample_run.json").read_text(encoding="utf-8"))
rows = score(rec, load_cases(), use_evidence=True)

failed = False
for kind, need in FLOOR.items():
    got = sum(r["correct"] for r in rows if r["kind"] == kind)
    print(f"{kind:<10} {got} correct (need >= {need})")
    failed |= got < need
wrong_hi = [r for r in rows if not r["correct"]
            and r["pred"] != "unknown_insufficient_evidence" and r["confidence"] >= 0.70]
print(f"confident wrong answers: {len(wrong_hi)} (need 0)")
failed |= bool(wrong_hi)
raise SystemExit(1 if failed else 0)