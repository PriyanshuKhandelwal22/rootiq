import json
from pathlib import Path

MIN_PER_CONDITION = 5  # need this many calm runs AND this many loaded runs


def load_observations(runs_dir: Path = Path("runs")):
    """Returns (per-test observations, per-run cpu list). Only runs with metrics count."""
    obs: dict[str, list[dict]] = {}
    run_cpu: list[tuple[bool, float]] = []
    for p in sorted(runs_dir.glob("run_*.json")):
        rec = json.loads(p.read_text(encoding="utf-8"))
        m = rec.get("metrics")
        if not m:
            continue
        stress = bool(rec.get("stress", False))
        run_cpu.append((stress, m["cpu_avg"]))
        for t in rec["tests"]:
            if t["status"] in ("passed", "failed", "error"):
                obs.setdefault(t["test_id"], []).append(
                    {"failed": t["status"] != "passed", "stress": stress}
                )
    return obs, run_cpu


def _rate(items: list[dict]) -> float:
    return sum(i["failed"] for i in items) / len(items)


def correlate(obs: dict[str, list[dict]]) -> list[dict]:
    results = []
    for test_id, items in obs.items():
        fails = sum(i["failed"] for i in items)
        if fails == 0 or fails == len(items):
            continue  # no outcome variation, nothing to explain
        calm = [i for i in items if not i["stress"]]
        loaded = [i for i in items if i["stress"]]
        if len(calm) < MIN_PER_CONDITION or len(loaded) < MIN_PER_CONDITION:
            continue
        calm_rate, loaded_rate = _rate(calm), _rate(loaded)
        diff = loaded_rate - calm_rate
        if diff >= 0.5:
            verdict = "load_sensitive"
        elif abs(diff) < 0.3:
            verdict = "no_load_effect"
        else:
            verdict = "inconclusive"
        results.append({
            "test_id": test_id, "verdict": verdict,
            "calm_runs": len(calm), "calm_fail_rate": calm_rate,
            "loaded_runs": len(loaded), "loaded_fail_rate": loaded_rate,
        })
    return results
