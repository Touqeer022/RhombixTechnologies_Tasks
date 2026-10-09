"""
crypto_utils.py
Cryptographic primitives for the SecureTag's protocol-level defenses.

- AES-256-GCM: encrypts the cardholder's real PAN (card number) at rest
  inside the tag's simulated memory. The wire protocol NEVER transmits
  this - only a backend "issuer" with the master key can ever recover it.
- HMAC-SHA256 challenge-response: proves tag authenticity to a reader that
  holds the shared key, without ever revealing the key or the real PAN
  over the air. An eavesdropper/skimmer who intercepts a response cannot
  derive the key (HMAC is one-way) and cannot replay it usefully because
  each response is bound to a fresh random challenge and a rotating
  session counter.
- Rotating identifiers: the tag presents a different pseudonymous ID on
  every power-up, which is standard practice in real contactless systems
  to prevent an attacker from tracking a card across multiple sightings.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def new_key(length: int = 32) -> bytes:
    return os.urandom(length)


def random_nonce(n: int = 16) -> bytes:
    return os.urandom(n)


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def aes_encrypt(key: bytes, plaintext: bytes):
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def mask_pan(pan: str) -> str:
    """Return a display-safe masked version, e.g. '**** **** **** 1234'."""
    digits = pan.replace(" ", "")
    last4 = digits[-4:]
    return f"**** **** **** {last4}"
