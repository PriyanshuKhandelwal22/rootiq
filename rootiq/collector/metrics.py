import threading
import time

import psutil

MAX_TIMELINE_POINTS = 300


class MetricsSampler:
    """Samples system CPU and memory in a background thread while tests run."""

    def __init__(self, interval: float = 0.1):
        self.interval = interval
        self.samples: list[dict] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0

    def _sample(self) -> None:
        self.samples.append({
            "t": round(time.perf_counter() - self._t0, 2),
            "cpu": psutil.cpu_percent(interval=None),
            "mem": psutil.virtual_memory().percent,
        })

    def start(self) -> None:
        psutil.cpu_percent(interval=None)  # first call is meaningless, so prime it
        self._t0 = time.perf_counter()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._sample()

    def stop(self) -> dict:
        self._stop.set()
        if self._thread:
            self._thread.join()
        if not self.samples:  # run finished before the first tick
            self._sample()

        cpu = [s["cpu"] for s in self.samples]
        mem = [s["mem"] for s in self.samples]
        step = max(1, len(self.samples) // MAX_TIMELINE_POINTS)
        return {
            "sample_count": len(self.samples),
            "interval_sec": self.interval,
            "cpu_avg": round(sum(cpu) / len(cpu), 1),
            "cpu_max": max(cpu),
            "mem_avg": round(sum(mem) / len(mem), 1),
            "mem_max": max(mem),
            "cpu_count": psutil.cpu_count(),
            "mem_total_mb": round(psutil.virtual_memory().total / 1024 / 1024),
            "timeline": self.samples[::step],
        }