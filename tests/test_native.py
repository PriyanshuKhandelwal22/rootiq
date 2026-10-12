import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path("native") / "crash_null.c"
EXE = Path("native") / "crash_null.exe"


@pytest.fixture(scope="module")
def crash_binary():
    if sys.platform != "win32":
        pytest.skip("Windows-only for now")
    subprocess.run(["gcc", "-g", "-O0", str(SRC), "-o", str(EXE)], check=True)
    return EXE


def test_null_pointer_crash(crash_binary):
    proc = subprocess.run([str(crash_binary)], capture_output=True, text=True)
    assert proc.returncode == 0, f"native program exited with code {proc.returncode}"