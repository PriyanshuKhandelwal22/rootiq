import hashlib
from collections import defaultdict


def make_fingerprint(failure: dict) -> str:
    """Stable 8-char ID from error type + normalized template + top-frame file."""
    frame_file = failure["top_frame"]["file"] or "unknown"
    key = "|".join([failure["error_type"], failure["template"], frame_file])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:8]


def group_failures(failures: list[dict]) -> dict[str, list[dict]]:
    groups = defaultdict(list)
    for f in failures:
        groups[f["fingerprint"]].append(f)
    return dict(groups)