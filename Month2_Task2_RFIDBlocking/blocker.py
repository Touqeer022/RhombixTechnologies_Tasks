"""
blocker.py
Ties the physical (signal/shielding) layer together with the protocol
(challenge-response + rate-limiting) layer into one "can this scan reach
and extract anything from the tag?" decision, and records every attempt
to the tamper-evident audit log.

This is the heart of "RFID blocking": blocking isn't one mechanism, it's
layered defense-in-depth —
  1. Physical layer (this module, via signal_model): if shielding/distance
     drops received power below the tag's threshold, the tag never powers
     on. This is an absolute block - no protocol trick gets around it.
  2. Protocol layer (rfid_tag.SecureTag): even if powered, a secure tag
     rate-limits suspicious reader behavior and never reveals the real
     card number regardless of who's asking.
A legacy tag only has protection from layer 1. A secure tag benefits from
both layers, which is why pairing "use secure cards" with "also shield
them" is the actual best-practice answer to RFID skimming.
"""

import time

import audit_log
import signal_model


def perform_scan(tag, reader, distance_m: float, shielding_db: float = 0.0, now: float = None):
    now = time.time() if now is None else now
    tag_id = getattr(tag, "tag_id", None) or getattr(tag, "uid", "unknown")

    sig = signal_model.evaluate(distance_m, shielding_db=shielding_db)
    if not sig.tag_powered:
        audit_log.log_event(
            "SCAN_ATTEMPT", tag_id, reader.reader_id, "BLOCKED_SHIELDING",
            detail=f"distance={distance_m}m shielding={shielding_db}dB "
                   f"received_power={sig.received_power_dbm:.1f}dBm (below tag threshold)",
        )
        return {"outcome": "BLOCKED_SHIELDING", "signal": sig, "result": None}

    result = reader.attempt_scan(tag, now=now)

    if result["status"] == "BLOCKED_RATE_LIMIT":
        audit_log.log_event(
            "SCAN_ATTEMPT", tag_id, reader.reader_id, "BLOCKED_RATE_LIMIT",
            detail="tag refused to respond: too many recent scan attempts from untrusted reader(s)",
        )
        return {"outcome": "BLOCKED_RATE_LIMIT", "signal": sig, "result": result}

    exposed = result.get("exposed_data") is not None
    identified = result.get("identified", False)
    outcome = "ALLOWED_EXPOSED" if exposed else ("ALLOWED_IDENTIFIED" if identified else "ALLOWED_OPAQUE")
    audit_log.log_event(
        "SCAN_ATTEMPT", tag_id, reader.reader_id, outcome,
        detail=f"signal_ok=True exposed_data={exposed} identified={identified}",
    )
    return {"outcome": outcome, "signal": sig, "result": result}
