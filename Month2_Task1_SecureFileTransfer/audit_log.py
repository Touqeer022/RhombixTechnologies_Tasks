"""
audit_log.py
Append-only, hash-chained audit log.

Every entry stores the SHA-256 hash of the previous entry alongside its own
data, then that combination is hashed to produce this entry's hash. This
means that modifying or deleting any historical entry breaks the chain for
every entry after it - so tampering is detectable by re-verifying the chain
(see verify_chain()). This does not make the log unforgeable by someone with
full write access to disk, but it does make silent, undetected tampering
much harder, and is a standard lightweight technique for audit-log integrity.
"""

import json
import os
import threading
import time

from crypto_utils import sha256_hex

LOG_FILE = os.path.join(os.path.dirname(__file__), "server_data", "audit_log.jsonl")
_lock = threading.Lock()

GENESIS_HASH = "0" * 64


def _last_hash() -> str:
    if not os.path.exists(LOG_FILE):
        return GENESIS_HASH
    last = None
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return GENESIS_HASH
    return json.loads(last)["entry_hash"]


def log_event(event: str, username: str, success: bool, detail: str = "", ip: str = ""):
    with _lock:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        prev_hash = _last_hash()
        record = {
            "timestamp": time.time(),
            "event": event,
            "username": username,
            "success": success,
            "detail": detail,
            "ip": ip,
            "prev_hash": prev_hash,
        }
        payload = json.dumps(record, sort_keys=True)
        record["entry_hash"] = sha256_hex((prev_hash + payload).encode())
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(record) + "\n")
        return record


def read_all():
    if not os.path.exists(LOG_FILE):
        return []
    entries = []
    with open(LOG_FILE, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    return entries


def verify_chain():
    """Returns (is_valid, first_broken_index_or_None)."""
    entries = read_all()
    prev_hash = GENESIS_HASH
    for i, record in enumerate(entries):
        expected_prev = record["prev_hash"]
        if expected_prev != prev_hash:
            return False, i
        stored_hash = record["entry_hash"]
        record_copy = {k: v for k, v in record.items() if k != "entry_hash"}
        payload = json.dumps(record_copy, sort_keys=True)
        recomputed = sha256_hex((prev_hash + payload).encode())
        if recomputed != stored_hash:
            return False, i
        prev_hash = stored_hash
    return True, None
