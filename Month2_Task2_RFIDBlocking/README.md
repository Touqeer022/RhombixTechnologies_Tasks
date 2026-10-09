# RFID Blocking System

A working simulation and testbed for RFID/NFC card skimming and the two
real defenses against it: **physical shielding** and **protocol-level
cryptographic protection**. Built for the Rhombix Technologies Cyber
Security internship, Month 2 / Task 2 ("RFID Blocking").

## The problem

> The radiofrequency identifying tags present in credit and debit cards
> can be used by card scanners for stealing sensitive data in the name
> of quick contactless payments.

Passive RFID/NFC tags (contactless cards, passports, access badges) have
no battery — they're powered by the reader's own radio field. An old-
style ("legacy") tag will answer *any* reader that can power it, in
plaintext. That's the vulnerability "RFID blocking" products exist to
address.

## What this project actually demonstrates

RFID blocking is not one trick — it's two independent layers of defense,
and this project implements and tests both:

**1. Physical layer — signal attenuation (`signal_model.py`)**
A log-distance RF power-budget model: received power drops with distance
and with any shielding (a Faraday sleeve/wallet) placed between card and
reader. If received power falls below the tag's power-on threshold, the
chip **physically cannot power up** — it's not refusing to answer, it's
incapable of it. This is what an RFID-blocking wallet/sleeve actually
does. (Deliberately simplified for teaching clarity — see Limitations.)

**2. Protocol layer — challenge-response crypto (`rfid_tag.py`, `reader.py`)**
Even without shielding, a *modern* secure tag never reveals the real card
number:
- A fresh **rotating pseudonymous ID** every power-up (can't be tracked
  across sightings by ID alone).
- **HMAC-SHA256 challenge-response** proves authenticity to a backend
  that holds the shared key — without ever transmitting the key or the
  real card number.
- The real card number is stored **AES-256-GCM encrypted at rest** on
  the tag; only the issuer backend holding the key can ever decrypt it.
- **Rate/anomaly-based self-blocking**: if an untrusted reader scans the
  tag too many times too quickly (the signature of a skimmer sweeping an
  area), the tag refuses to respond for a cooldown period — a
  software-level block that works even with zero physical shielding.

Every scan attempt (allowed, blocked by shielding, blocked by rate
limiting, identified or not) is written to a **tamper-evident,
hash-chained audit log** (same integrity technique used in the Month 2
secure-file-transfer task), so the system also demonstrates proper
traceability of access attempts.

## Project layout

```
rfid_blocking_system/
├── signal_model.py    # RF power-budget model: distance + shielding -> tag powered?
├── crypto_utils.py    # AES-256-GCM (data at rest) + HMAC-SHA256 (challenge-response)
├── rfid_tag.py        # LegacyTag (vulnerable) and SecureTag (rotating ID + crypto + rate-limit)
├── reader.py           # Backend (key-holding issuer), POSReader (legit), SkimmerReader (attacker)
├── blocker.py           # Orchestrates signal-gating + protocol + audit logging
├── audit_log.py          # Hash-chained, tamper-evident scan log
├── simulate.py            # Runnable end-to-end demo with 5 scenarios
├── tests/test_rfid.py      # 13 automated tests proving every security claim above
└── requirements.txt
```

## Setup & run

```bash
pip install -r requirements.txt
python3 simulate.py          # runs the full demo with printed commentary
python3 -m pytest tests/ -v   # runs the automated test suite
```

(On Windows: same commands with `python` instead of `python3`.)

## What the demo shows (5 scenarios)

1. **Legacy card, no shielding** → skimmer reads the card number in the clear.
2. **Legacy card, with a blocking sleeve** → skimmer's reader can't even
   power the chip. Fully blocked.
3. **Secure card, no shielding** → skimmer *does* power the tag and *does*
   get a response, but it's just an opaque rotating ID + HMAC — no usable
   card data, because the protocol never sends it.
4. **Secure card, legitimate checkout terminal** → the backend correctly
   identifies the account using its key, while the card itself never
   announced who it was.
5. **Secure card under rapid repeated skimming** → after a few quick
   attempts from an untrusted reader, the tag stops responding entirely
   for a cooldown window — protocol-level blocking with no shielding at all.

## Threat model & limitations

- **`signal_model.py` is illustrative, not an RF-engineering tool.** It
  captures the right *shape* of the problem (attenuation with distance
  and shielding) using simplified log-distance path loss, not a
  calibrated antenna/EMC simulation. Don't use the dB numbers as
  real-world engineering guidance.
- **The crypto here models the concept**, not a specific real-world
  standard (EMV, ISO/IEC 14443, DESFire, etc. all have their own,
  more elaborate key-management and session protocols). The HMAC
  challenge-response and rotating-ID approach is conceptually accurate
  to how real contactless systems avoid broadcasting static identifiers,
  but isn't a drop-in implementation of any specific card scheme.
- **Rate-limiting is a known-pattern heuristic**, not foolproof: a patient
  attacker who scans slowly, below the threshold, isn't caught by it —
  which is exactly why it's described here as one layer of defense,
  not the whole solution. Physical shielding plus cryptography is the
  actual answer; rate-limiting is a bonus layer.
- **The `Backend.identify()` resync-window search is O(tags × window)**,
  fine for a demo with a handful of cards; a real issuer uses indexed
  lookups and tighter resynchronization protocols at scale.

## Requirements

- Python 3.9+
- `cryptography`, `pytest` (see requirements.txt)
