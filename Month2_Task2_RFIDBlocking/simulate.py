"""
simulate.py
End-to-end demo: runs a series of realistic scenarios through the full
stack (signal model -> tag -> reader -> backend -> audit log) and prints
a clear before/after comparison, then verifies the audit log's integrity.

Run: python3 simulate.py
"""

import time

import audit_log
import signal_model
from blocker import perform_scan
from reader import Backend, POSReader, SkimmerReader
from rfid_tag import LegacyTag, SecureTag


def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(label, out):
    sig = out["signal"]
    print(f"{label:<55} power={sig.received_power_dbm:7.1f}dBm -> {out['outcome']}")


def main():
    audit_log.reset()

    backend = Backend()
    pos = POSReader("store-pos-terminal-01", backend)
    skimmer = SkimmerReader("unknown-skimmer")

    # ------------------------------------------------------------------
    banner("SCENARIO 1: Legacy (unencrypted) RFID card - no shielding")
    legacy_card = LegacyTag(uid="UID-AC12F", pan="4111 1111 1111 1234")
    out = perform_scan(legacy_card, skimmer, distance_m=0.05, shielding_db=signal_model.SHIELDING_NONE_DB)
    show("Skimmer @ 5cm, no shielding", out)
    if out["result"] and out["result"].get("exposed_data"):
        print(f"  -> ATTACKER OBTAINED: {out['result']['exposed_data']}")
        print("  This is exactly why legacy contactless cards are considered vulnerable.")

    banner("SCENARIO 2: Legacy card - WITH an RFID-blocking sleeve")
    legacy_card2 = LegacyTag(uid="UID-AC12F", pan="4111 1111 1111 1234")
    out = perform_scan(legacy_card2, skimmer, distance_m=0.05, shielding_db=signal_model.SHIELDING_THIN_SLEEVE_DB)
    show("Skimmer @ 5cm, basic blocking sleeve", out)
    print("  -> Physical shielding alone fully protects even an insecure legacy tag:")
    print("     the chip never receives enough power to respond at all.")

    # ------------------------------------------------------------------
    banner("SCENARIO 3: Modern secure card - attacker skims with NO shielding")
    secure_card = SecureTag(tag_id="ACCT-7788", pan="4111 1111 1111 5678", trusted_reader_ids={"store-pos-terminal-01"})
    backend.register(secure_card.tag_id, secure_card.key)
    out = perform_scan(secure_card, skimmer, distance_m=0.05, shielding_db=signal_model.SHIELDING_NONE_DB)
    show("Skimmer @ 5cm, no shielding", out)
    captured = out["result"].get("captured_opaque") if out["result"] else None
    print(f"  -> Attacker DID power the tag and DID get a response: {captured}")
    print("  -> But this is a one-time rotating ID + HMAC the attacker cannot decode:")
    print(f"     masked card number on the card itself: {secure_card.masked_pan}")
    print("     Even a successful physical read exposes NOTHING usable, because the")
    print("     protocol never transmits the real card number.")

    # ------------------------------------------------------------------
    banner("SCENARIO 4: Same secure card - legitimate store checkout")
    secure_card2 = SecureTag(tag_id="ACCT-9911", pan="4111 1111 1111 9012", trusted_reader_ids={"store-pos-terminal-01"})
    backend.register(secure_card2.tag_id, secure_card2.key)
    out = perform_scan(secure_card2, pos, distance_m=0.02, shielding_db=signal_model.SHIELDING_NONE_DB)
    show("Legit POS @ 2cm", out)
    res = out["result"]
    print(f"  -> Backend identified account: {res.get('tag_id')} (identified={res.get('identified')})")
    print("     The backend can only do this because it holds the shared key -")
    print("     the card itself never announced who it was.")

    # ------------------------------------------------------------------
    banner("SCENARIO 5: Software-level blocking - rapid skimming attempts")
    secure_card3 = SecureTag(tag_id="ACCT-3344", pan="4111 1111 1111 3344", trusted_reader_ids={"store-pos-terminal-01"})
    backend.register(secure_card3.tag_id, secure_card3.key)
    now = time.time()
    for i in range(6):
        out = perform_scan(secure_card3, skimmer, distance_m=0.03, shielding_db=0.0, now=now + i * 0.3)
        show(f"Skimmer attempt #{i + 1} (rapid, {i * 0.3:.1f}s apart)", out)
    print("  -> After a few rapid attempts from an untrusted reader, the tag")
    print("     itself refuses to respond for a cooldown period - a software-level")
    print("     block that works even with zero physical shielding.")

    # ------------------------------------------------------------------
    banner("AUDIT LOG")
    valid, broken_at = audit_log.verify_chain()
    print(f"Chain integrity: {'VALID' if valid else f'BROKEN at entry {broken_at}'}")
    for e in audit_log.read_all():
        print(f"  [{e['outcome']:<20}] tag={e['tag_id']:<12} reader={e['reader_id']:<22} {e['detail']}")

    print("\nDone. Full attempt-by-attempt log saved to scan_log.jsonl")


if __name__ == "__main__":
    main()
