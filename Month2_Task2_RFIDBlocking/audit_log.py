"""
audit_log.py
Append-only, hash-chained audit log for every scan attempt (authorized,
unauthorized, blocked-by-shielding, or rate-limited). Each entry embeds
the hash of the previous entry, so silently editing or deleting a past
entry breaks the chain for everything after it - this makes tampering
detectable via verify_chain(), the same tamper-evidence pattern used for
access logs in regulated card-security environments.
"""

import json
import os
import threading
import time

from crypto_utils import hashlib

LOG_FILE = os.path.join(os.path.dirname(__file__), "scan_log.jsonl")
_lock = threading.Lock()
GENESIS_HASH = "0" * 64


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _last_hash() -> str:
    if not os.path.exists(LOG_FILE):
        return GENESIS_HASH
    last = None
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    return json.loads(last)["entry_hash"] if last else GENESIS_HASH


def log_event(event: str, tag_id: str, reader_id: str, outcome: str, detail: str = ""):
    with _lock:
        prev_hash = _last_hash()
        record = {
            "timestamp": time.time(),
            "event": event,       # e.g. SCAN_ATTEMPT
            "tag_id": tag_id,
            "reader_id": reader_id,
            "outcome": outcome,   # ALLOWED / BLOCKED_SHIELDING / BLOCKED_RATE_LIMIT / BLOCKED_UNTRUSTED
            "detail": detail,
            "prev_hash": prev_hash,
        }
        payload = json.dumps(record, sort_keys=True)
        record["entry_hash"] = _sha256_hex((prev_hash + payload).encode())
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
        return record


def read_all():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return [json.loads(line) for line in f if line.strip()]


def verify_chain():
    entries = read_all()
    prev_hash = GENESIS_HASH
    for i, record in enumerate(entries):
        if record["prev_hash"] != prev_hash:
            return False, i
        record_copy = {k: v for k, v in record.items() if k != "entry_hash"}
        payload = json.dumps(record_copy, sort_keys=True)
        recomputed = _sha256_hex((prev_hash + payload).encode())
        if recomputed != record["entry_hash"]:
            return False, i
        prev_hash = record["entry_hash"]
    return True, None


def reset():
    """Used by tests/demo to start from a clean log file."""
    with _lock:
        if os.path.exists(LOG_FILE):
            os.remove(LOG_FILE)
