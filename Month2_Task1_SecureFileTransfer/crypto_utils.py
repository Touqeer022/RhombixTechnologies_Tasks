"""
crypto_utils.py
Core cryptographic primitives for the Secure File Transfer app.

Design summary
--------------
- RSA-2048 keypairs: generated CLIENT-SIDE only. The private key never
  leaves the client machine, so the server (and anyone who compromises it)
  can never decrypt file contents. This is what makes the transfer
  end-to-end (E2E) rather than just transport-encrypted.
- AES-256-GCM: used to encrypt file contents. GCM is an AEAD cipher, so it
  gives us confidentiality AND integrity (a forged/tampered ciphertext will
  fail to decrypt) in one primitive.
- RSA-OAEP: used to "wrap" (encrypt) the random AES file key for each
  authorized recipient, using that recipient's RSA public key. Only the
  holder of the matching private key can unwrap it.
- PBKDF2-HMAC-SHA256: used both for password hashing (auth) and for
  deriving a local key-encryption-key that protects each user's private
  key at rest on disk.
"""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RSA_KEY_SIZE = 2048
PBKDF2_ITERATIONS = 390_000  # OWASP-recommended-ish minimum for PBKDF2-HMAC-SHA256


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def derive_key(password: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key from a password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def hash_password(password: str, salt: bytes) -> str:
    """One-way password hash for storage on the server (auth only)."""
    return derive_key(password, salt, 32).hex()


# ---------------------------------------------------------------------------
# RSA keypair management (client-side only)
# ---------------------------------------------------------------------------

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


def encrypt_private_key_blob(private_key, password: str):
    """
    Encrypt a private key PEM at rest using a password-derived AES-256-GCM key.
    Returns (ciphertext_b64, nonce_b64, salt_b64) for local storage.
    Nothing here is ever transmitted to the server.
    """
    pem = private_key_to_pem(private_key)
    salt = new_salt()
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, pem, None)
    return b64(ct), b64(nonce), b64(salt)


def decrypt_private_key_blob(ct_b64: str, nonce_b64: str, salt_b64: str, password: str):
    key = derive_key(password, unb64(salt_b64))
    pem = AESGCM(key).decrypt(unb64(nonce_b64), unb64(ct_b64), None)
    return load_private_key_pem(pem)


# ---------------------------------------------------------------------------
# File encryption (AES-256-GCM) + key wrapping (RSA-OAEP)
# ---------------------------------------------------------------------------

def aes_encrypt_bytes(plaintext: bytes):
    """Returns (aes_key, nonce, ciphertext). ciphertext includes the GCM tag."""
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return key, nonce, ciphertext


def aes_decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Raises cryptography.exceptions.InvalidTag if the data was tampered with."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def rsa_wrap_key(public_key, aes_key: bytes) -> bytes:
    return public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_unwrap_key(private_key, wrapped: bytes) -> bytes:
    return private_key.decrypt(
        wrapped,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
