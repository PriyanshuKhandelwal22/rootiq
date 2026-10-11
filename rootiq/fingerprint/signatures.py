import hashlib
from collections import defaultdict


def make_fingerprint(failure: dict) -> str:
    """Stable 8-char ID from error type + normalized template + where it happened.

    "Where" is the last frame in project code. If the exception was finally raised
    in a different file (a library), that file is part of the key too. When both
    are the same file the key is just that file, so those fingerprints don't change.
    """
    frame = failure["top_frame"]
    own = frame["file"] or "unknown"
    raised = frame.get("raised_in") or own
    where = own if raised == own else f"{own}>{raised}"
    key = "|".join([failure["error_type"], failure["template"], where])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def group_failures(failures: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for f in failures:
        groups[f["fingerprint"]].append(f)
    return dict(groups)