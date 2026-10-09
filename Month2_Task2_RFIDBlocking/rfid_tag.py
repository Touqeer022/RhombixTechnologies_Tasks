"""
rfid_tag.py
Two tag implementations representing the "before" and "after" of RFID
security, so the demo can show concretely what blocking a legacy card
protects against and how a secure protocol protects even against a
successful read.

LegacyTag:
    Models an old-style RFID tag that answers any reader in range with its
    data in the clear - this is the vulnerable baseline. If a legacy tag
    is read, the card number is exposed, full stop. The ONLY defense
    available for a tag like this is physical: keep readers out of range
    (shielding/distance).

SecureTag:
    Models a modern contactless-card-style tag:
      - Rotating identifier: a new pseudonymous ID every power-up, so a
        tag can't be tracked across sightings just by its ID.
      - Challenge-response using a shared HMAC key: the tag never reveals
        the real card number or the key - it proves authenticity
        cryptographically. Only a backend holding the key can verify the
        response and resolve it to the account.
      - Rate-based self-protection: if it gets scanned unusually fast or
        by not-previously-seen readers many times in a short window
        (typical of a skimmer sweeping an area), it refuses to respond
        for a cooldown period - a software-level "block" independent of
        any physical shielding.
"""

import time
from collections import deque

import crypto_utils as cu


class LegacyTag:
    """Vulnerable baseline: responds to anyone in range with plaintext data."""

    def __init__(self, uid: str, pan: str):
        self.uid = uid
        self.pan = pan  # stored and transmitted in the clear - that's the vulnerability

    def respond(self, reader_id: str):
        # No authentication, no encryption: whoever can power the chip gets the data.
        return {"uid": self.uid, "pan": self.pan}


class SecureTag:
    RATE_LIMIT_WINDOW_SECONDS = 5.0
    RATE_LIMIT_MAX_ATTEMPTS = 3       # more than this many scans in the window -> suspicious
    COOLDOWN_SECONDS = 10.0

    def __init__(self, tag_id: str, pan: str, trusted_reader_ids=None):
        self.tag_id = tag_id
        self.key = cu.new_key()
        nonce, ciphertext = cu.aes_encrypt(self.key, pan.encode())
        self._enc_pan_nonce = nonce
        self._enc_pan_ciphertext = ciphertext
        self.masked_pan = cu.mask_pan(pan)
        self.trusted_reader_ids = set(trusted_reader_ids or [])
        self._counter = 0
        self._recent_attempts = deque()  # timestamps of recent scan attempts (any reader)
        self._cooldown_until = 0.0

    # -- internal: software-level anomaly/rate blocking -----------------
    def _check_rate_limit(self, now: float, reader_id: str) -> bool:
        """Returns True if this attempt should be blocked as suspicious."""
        if now < self._cooldown_until:
            return True

        window_start = now - self.RATE_LIMIT_WINDOW_SECONDS
        while self._recent_attempts and self._recent_attempts[0] < window_start:
            self._recent_attempts.popleft()
        self._recent_attempts.append(now)

        is_untrusted = reader_id not in self.trusted_reader_ids
        if is_untrusted and len(self._recent_attempts) > self.RATE_LIMIT_MAX_ATTEMPTS:
            self._cooldown_until = now + self.COOLDOWN_SECONDS
            return True
        return False

    # -- public protocol --------------------------------------------------
    def respond(self, reader_id: str, challenge: bytes, now: float = None):
        """
        Returns (status, payload):
          status "BLOCKED_RATE_LIMIT" -> payload is None (tag stays silent)
          status "OK" -> payload is {"rotating_id", "hmac_response", "counter"}
        Never returns the real PAN or the key, regardless of status.
        """
        now = time.time() if now is None else now
        if self._check_rate_limit(now, reader_id):
            return "BLOCKED_RATE_LIMIT", None

        self._counter += 1
        rotating_id = cu.hashlib.sha256(f"{self.tag_id}:{self._counter}".encode()).hexdigest()[:16]
        message = challenge + rotating_id.encode() + str(self._counter).encode()
        response = cu.hmac_sha256(self.key, message)
        return "OK", {
            "rotating_id": rotating_id,
            "hmac_response": response,
            "counter": self._counter,
        }

    def decrypt_real_pan(self) -> str:
        """Only the issuer/backend - which holds self.key - can call this meaningfully."""
        return cu.aes_decrypt(self.key, self._enc_pan_nonce, self._enc_pan_ciphertext).decode()
