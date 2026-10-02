import re

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"
)
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::(\d+))?\b")
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
NUM_RE = re.compile(r"(?<![\w.])\d+(?:\.\d+)?")

# "E   KeyError: 'data'"  ->  KeyError
ERROR_LINE_RE = re.compile(
    r"^E\s+([A-Za-z_][\w.]*(?:Error|Exception|Exit|Interrupt)):", re.M
)
# "tests\test_basic.py:9: AssertionError"  ->  AssertionError
LOCATION_RE = re.compile(r"^\S+:\d+: ([A-Za-z_][\w.]*)\s*$", re.M)
FRAME_RE = re.compile(r"([^\s\\/]+\.py):(\d+):")


def normalize_message(text: str) -> str:
    """Replace variable details with placeholders so similar errors match."""
    text = UUID_RE.sub("<UUID>", text)
    text = TS_RE.sub("<TS>", text)
    text = IP_RE.sub(lambda m: "<IP>:<PORT>" if m.group(1) else "<IP>", text)
    text = HEX_RE.sub("<HEX>", text)
    text = NUM_RE.sub("<NUM>", text)
    return " ".join(text.split())


def extract_error_type(message: str | None, traceback: str | None) -> str:
    tb = traceback or ""
    m = ERROR_LINE_RE.search(tb)
    if m:
        return m.group(1)
    m = LOCATION_RE.search(tb)
    if m:
        return m.group(1)
    if (message or "").startswith("assert"):
        return "AssertionError"
    return "UnknownError"


def extract_top_frame(traceback: str | None) -> dict:
    """The last file:line in the traceback is where the failure surfaced."""
    frames = FRAME_RE.findall(traceback or "")
    if not frames:
        return {"file": None, "line": None}
    file, line = frames[-1]
    return {"file": file, "line": int(line)}


def normalize_failure(test: dict) -> dict:
    message = test.get("message") or ""
    return {
        "test_id": test["test_id"],
        "error_type": extract_error_type(message, test.get("traceback")),
        "template": normalize_message(message),
        "top_frame": extract_top_frame(test.get("traceback")),
        "raw_message": message,
    }