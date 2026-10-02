import time

BUDGET_SEC = 0.06


def test_cpu_bound_work_meets_deadline():
    start = time.perf_counter()
    sum(i * i for i in range(500_000))
    elapsed = time.perf_counter() - start
    assert elapsed < BUDGET_SEC, f"work took {elapsed:.3f}s, budget {BUDGET_SEC}s"
