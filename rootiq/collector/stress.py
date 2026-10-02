import os
import subprocess
import sys


class CpuStress:
    """Starts busy-loop processes to load the CPU. Always call stop()."""

    def __init__(self, workers: int | None = None):
        self.workers = workers or (os.cpu_count() or 2) * 3
        self.procs: list[subprocess.Popen] = []

    def start(self) -> None:
        for _ in range(self.workers):
            self.procs.append(
                subprocess.Popen([sys.executable, "-c", "while True: pass"])
            )

    def stop(self) -> None:
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            p.wait()
        self.procs.clear()
