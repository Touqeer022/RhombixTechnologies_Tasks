# Secure File Transfer

A client/server file transfer application with genuine end-to-end
encryption, authenticated integrity checking, role-based access control,
and a tamper-evident audit log.

## Why it's "end-to-end"

Most "secure" file transfer tools only encrypt the network connection
(TLS) — the server itself can still read every file that passes through
it. This app goes further:

- Every user generates an **RSA-2048 keypair on their own machine**. The
  private key **never leaves the client** — only the public key is
  registered with the server.
- Each file is encrypted **client-side** with a fresh random **AES-256-GCM**
  key before it's ever sent.
- That AES key is then individually **wrapped (RSA-OAEP)** for the owner
  and every explicitly authorized recipient, using *their* public keys.
- The server stores and relays ciphertext + wrapped keys only. It has no
  key capable of decrypting file contents — even a fully compromised
  server, or a subpoena served on the operator, cannot expose file
  contents, only encrypted blobs and metadata (who sent what to whom,
  when).

On top of that, the client-server *connection* itself is wrapped in TLS
1.2+, so metadata and credentials aren't exposed on the wire either.

## Security properties

| Property | Mechanism |
|---|---|
| Confidentiality (files) | AES-256-GCM, key never touches the server |
| Confidentiality (transport) | TLS 1.2+ socket |
| Integrity | AES-GCM auth tag (tamper → decryption fails) + SHA-256 re-check after decrypt |
| Authentication | PBKDF2-HMAC-SHA256 password hashing (390k iterations), session tokens |
| Access control | Per-file recipient list; server checks membership before releasing ciphertext |
| Non-repudiation of admin action / audit trail | Hash-chained, append-only audit log |
| Key-at-rest protection | Each user's private key is stored locally, AES-GCM-encrypted with a password-derived key |

## Project layout

```
secure_file_transfer/
├── server.py         # TLS socket server, protocol handlers, ACL enforcement
├── client.py         # CLI client — all encryption/decryption happens here
├── crypto_utils.py    # RSA/AES/PBKDF2 primitives
├── auth.py            # user store, password hashing, sessions, RBAC
├── audit_log.py       # hash-chained audit logging
├── gen_cert.sh         # generates a self-signed TLS cert for the server
├── run_test.sh          # end-to-end smoke test (register/upload/download/deny/logs)
├── requirements.txt
├── server_data/        # created at runtime: users.json, files.json, audit_log.jsonl, cert
└── client_data/         # created at runtime: each user's locally-encrypted private key
```

## Setup

**macOS / Linux:**
```bash
pip install -r requirements.txt
./gen_cert.sh               # or: python3 gen_cert.py
python3 server.py           # starts the server on 0.0.0.0:9443
```

**Windows (PowerShell or cmd):**
```powershell
pip install -r requirements.txt
python gen_cert.py          # cross-platform cert generator, no openssl/bash needed
python server.py            # starts the server on 0.0.0.0:9443
```
(`gen_cert.sh` is a bash script and won't run directly in PowerShell — use
`gen_cert.py` instead, which does the same thing with pure Python.
Also note PowerShell doesn't support `&&` the way bash does — run each
command on its own line, or separate with `;`.)

In another terminal:

```bash
python3 client.py register alice AlicePass123!
python3 client.py register bob   BobPass456!

python3 client.py upload alice AlicePass123! ./somefile.pdf --to bob
python3 client.py list   bob   BobPass456!
python3 client.py download bob BobPass456! <file_id> ./downloads/

python3 client.py logs alice AlicePass123!   # requires --role admin at registration
```
(On Windows, just use `python` instead of `python3`.)

Run `./run_test.sh` for a full automated walkthrough (register two users,
upload+share a file, download it, prove an unauthorized third user is
denied, print the audit trail, and show that the server's stored blob is
unreadable ciphertext).

## Protocol

Length-prefixed JSON messages over TLS (`REGISTER`, `LOGIN`, `GET_PUBLIC_KEY`,
`UPLOAD`, `LIST_FILES`, `DOWNLOAD`, `GET_LOGS`). Binary data (ciphertext,
wrapped keys) is base64-encoded within the JSON payload for simplicity.

## Threat model & limitations (read before any real deployment)

This is a solid architectural demonstration, not a production-hardened
product. Known limitations:

- **Self-signed TLS cert** — fine for a demo, but real deployment needs a
  CA-issued cert and proper hostname verification (the client currently
  disables hostname checking for the demo cert).
- **No public-key trust verification (TOFU/PKI missing)** — a malicious
  server could substitute a different public key for a "recipient" during
  `GET_PUBLIC_KEY` and MITM the key-wrapping step. A real system needs a
  key-verification mechanism (fingerprint comparison, a certificate
  authority, or a key-transparency log) so clients don't blindly trust
  the server's account of who owns which public key.
- **Lost password = lost data** — since the private key is only stored
  locally, encrypted with a password-derived key, losing the password
  (with no backup of the decrypted key) makes that user's files
  permanently unrecoverable. This is inherent to true E2E encryption but
  should be surfaced clearly to users.
- **No file revocation** — once a recipient has downloaded and decrypted
  a file, the app can't "unshare" that copy. Revoking access to future
  downloads is possible (would need a small extension) but past
  plaintext already on a recipient's disk is out of scope for any
  software-only control.
- **In-memory rate limiting is absent** — a production system should add
  login-attempt throttling / account lockout to slow brute-force attacks
  against the PBKDF2 hash.
- **Single admin role granularity** — only two roles (`user`, `admin`)
  are modeled; real deployments typically need more granular permissions.
- **Audit log is hash-chained but not remotely anchored** — this makes
  *silent* local tampering detectable, but someone with full write access
  to the server disk could still regenerate a consistent-looking chain
  from scratch. For stronger guarantees, periodically publish the chain's
  latest hash to an external, append-only store (e.g., a separate
  write-once log service).

## Requirements

- Python 3.9+
- `cryptography` (see requirements.txt)
