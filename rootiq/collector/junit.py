import xml.etree.ElementTree as ET
from pathlib import Path

STATUS_BY_TAG = {"failure": "failed", "error": "error", "skipped": "skipped"}


def parse_junit(path: Path) -> list[dict]:
    """Turn a pytest JUnit XML file into a list of per-test dicts."""
    if not path.exists():
        return []

    tests = []
    for tc in ET.parse(path).getroot().iter("testcase"):
        status, message, traceback = "passed", None, None
        for tag, mapped in STATUS_BY_TAG.items():
            el = tc.find(tag)
            if el is not None:
                status = mapped
                message = el.get("message")
                traceback = el.text
                break

        suite = tc.get("classname", "")
        name = tc.get("name", "")
        tests.append({
            "test_id": f"{suite}::{name}",
            "suite": suite,
            "name": name,
            "status": status,
            "duration_sec": float(tc.get("time", 0)),
            "message": message,
            "traceback": traceback,
        })
    return tests