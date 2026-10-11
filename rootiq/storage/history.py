import json
import sqlite3
from pathlib import Path

DB_PATH = Path("runs") / "rootiq.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    timestamp TEXT,
    exit_code INTEGER
);
CREATE TABLE IF NOT EXISTS failures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT,
    test_id TEXT,
    fingerprint TEXT,
    error_type TEXT,
    template TEXT,
    root_cause TEXT,
    confidence REAL,
    diagnosis_json TEXT,
    UNIQUE(run_id, test_id)
);
CREATE INDEX IF NOT EXISTS idx_fp ON failures(fingerprint);
"""


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    return conn


def save_run(rec: dict, failures: list[dict], diagnoses: dict) -> None:
    """failures: normalized failures with fingerprint. diagnoses: fingerprint -> diagnosis."""
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO runs VALUES (?, ?, ?)",
            (rec["run_id"], rec["timestamp"], rec["exit_code"]),
        )
        for f in failures:
            d = diagnoses[f["test_id"]]
            conn.execute(
                "INSERT OR REPLACE INTO failures "
                "(run_id, test_id, fingerprint, error_type, template, "
                "root_cause, confidence, diagnosis_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rec["run_id"], f["test_id"], f["fingerprint"], f["error_type"],
                 f["template"], d["root_cause"], d["confidence"], json.dumps(d)),
            )


def history_for(fingerprint: str, exclude_run: str) -> dict:
    """How often has this fingerprint appeared in OTHER runs?"""
    with connect() as conn:
        row = conn.execute(
            "SELECT COUNT(DISTINCT run_id), MIN(run_id), MAX(run_id) "
            "FROM failures WHERE fingerprint = ? AND run_id != ?",
            (fingerprint, exclude_run),
        ).fetchone()
    return {"runs_seen": row[0], "first_seen": row[1], "last_seen": row[2]}