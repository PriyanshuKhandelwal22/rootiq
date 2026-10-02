import random


def test_flaky_timing():
    # Intentionally nondeterministic: fails roughly 40% of the time
    assert random.random() > 0.4