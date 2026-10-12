import subprocess
import sys
from pathlib import Path

import pytest

from rootiq.collector.netprobe import observed_native_run

SRC = Path("native") / "crash_null.c"
EXE = Path("native") / "crash_null.exe"


@pytest.fixture(scope="module")
def crash_binary():
    if sys.platform != "win32":
        pytest.skip("Windows-only for now")
    subprocess.run(["gcc", "-g", "-O0", str(SRC), "-o", str(EXE)], check=True)
    return EXE


def test_null_pointer_crash(crash_binary):
    proc = observed_native_run([str(crash_binary)])
    assert proc.returncode == 0, f"native program exited with code {proc.returncode}"
