import json
import os
import socket
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


def _current_test_id() -> str | None:
    """Rebuild the same test_id format the JUnit parser produces."""
    cur = os.environ.get("PYTEST_CURRENT_TEST", "")
    nodeid = cur.rsplit(" ", 1)[0]  # strip the trailing "(call)"
    if "::" not in nodeid:
        return None
    file, name = nodeid.split("::", 1)
    suite = file.replace("\\", ".").replace("/", ".").removesuffix(".py")
    return f"{suite}::{name}"


def log_evidence(item: dict) -> None:
    """Append one evidence record. Does nothing when run outside RootIQ."""
    path = os.environ.get("ROOTIQ_EVIDENCE_FILE")
    if not path:
        return
    item = {"test_id": _current_test_id(),
            "ts": datetime.now(timezone.utc).isoformat(), **item}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(item) + "\n")


@contextmanager
def observe_socket(host: str, port: int, phase: str):
    """Wrap a socket action. Records the outcome, then re-raises the real error."""
    start = time.perf_counter()
    outcome, detail = "ok", None
    try:
        yield
    except TimeoutError as e:
        outcome, detail = "timeout", str(e)
        raise
    except ConnectionRefusedError as e:
        outcome, detail = "refused", str(e)
        raise
    except socket.gaierror as e:
        outcome, detail = "dns_error", str(e)
        raise
    except OSError as e:
        outcome, detail = "os_error", str(e)
        raise
    finally:
        log_evidence({
            "type": "socket",
            "host": host,
            "port": port,
            "phase": phase,  # "connect" or "read"
            "outcome": outcome,
            "elapsed_ms": round((time.perf_counter() - start) * 1000, 1),
            "detail": detail,
        })


def read_evidence(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]
