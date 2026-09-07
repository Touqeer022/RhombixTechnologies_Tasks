"""
client.py
Secure File Transfer - client CLI.

All cryptography that matters for confidentiality happens HERE, before
anything touches the network:
  - RSA keypair is generated locally on first `register` and the private
    key is stored locally, encrypted at rest with a password-derived key.
    It is never transmitted.
  - On `upload`, the file is encrypted locally with a fresh random
    AES-256-GCM key, which is then wrapped (RSA-OAEP) individually for the
    owner and every specified recipient. Only ciphertext + wrapped keys go
    over the wire.
  - On `download`, the ciphertext is decrypted locally after unwrapping the
    AES key with the user's own private key, and the SHA-256 is
    re-verified against what was recorded at upload time.

Usage:
  python client.py register  <username> <password> [--role admin]
  python client.py login     <username> <password>
  python client.py upload    <username> <password> <filepath> [--to alice,bob]
  python client.py list      <username> <password>
  python client.py download  <username> <password> <file_id> <output_dir>
  python client.py logs      <username> <password>          # admin only
  python client.py verify-log <username> <password>          # admin only
"""

import argparse
import json
import os
import socket
import ssl
import struct
import sys

import crypto_utils as cu

HOST = "127.0.0.1"
PORT = 9443
CLIENT_DATA = os.path.join(os.path.dirname(__file__), "client_data")
CERT_FILE = os.path.join(os.path.dirname(__file__), "server_data", "server.crt")


# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------

def connect():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if os.path.exists(CERT_FILE):
        ctx.load_verify_locations(CERT_FILE)
        ctx.check_hostname = False  # self-signed demo cert has CN=localhost only
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        print("WARNING: server certificate not found locally; connection will not be verified.")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((HOST, PORT))
    return ctx.wrap_socket(raw, server_hostname="localhost")


def send_msg(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    conn.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_msg(conn):
    header = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", header)
    data = recv_exact(conn, length)
    return json.loads(data.decode("utf-8"))


def request(cmd, **kwargs):
    conn = connect()
    try:
        send_msg(conn, {"cmd": cmd, **kwargs})
        return recv_msg(conn)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Local private-key storage
# ---------------------------------------------------------------------------

def local_key_path(username):
    os.makedirs(CLIENT_DATA, exist_ok=True)
    return os.path.join(CLIENT_DATA, f"{username}.privkey.json")


def save_local_private_key(username, private_key, password):
    ct_b64, nonce_b64, salt_b64 = cu.encrypt_private_key_blob(private_key, password)
    with open(local_key_path(username), "w") as f:
        json.dump({"ciphertext": ct_b64, "nonce": nonce_b64, "salt": salt_b64}, f)


def load_local_private_key(username, password):
    path = local_key_path(username)
    if not os.path.exists(path):
        raise SystemExit(
            f"No local private key found for '{username}' on this machine "
            f"({path}). You must register from this machine, or restore your "
            f"key backup, before you can log in."
        )
    with open(path, "r") as f:
        blob = json.load(f)
    try:
        return cu.decrypt_private_key_blob(blob["ciphertext"], blob["nonce"], blob["salt"], password)
    except Exception:
        raise SystemExit("Failed to decrypt local private key - wrong password?")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_register(args):
    private_key, public_key = cu.generate_rsa_keypair()
    pubkey_pem = cu.public_key_to_pem(public_key).decode()
    resp = request(
        "REGISTER",
        username=args.username,
        password=args.password,
        public_key_pem=pubkey_pem,
        role=args.role,
    )
    if not resp["ok"]:
        print(f"Registration failed: {resp['error']}")
        sys.exit(1)
    save_local_private_key(args.username, private_key, args.password)
    print(f"Registered '{args.username}' (role={args.role}).")
    print(f"Private key stored locally (encrypted) at {local_key_path(args.username)}")
    print("Back this file up - if it's lost, encrypted files can never be recovered.")


def cmd_login(args):
    resp = request("LOGIN", username=args.username, password=args.password)
    if not resp["ok"]:
        print(f"Login failed: {resp['error']}")
        sys.exit(1)
    load_local_private_key(args.username, args.password)  # sanity check it decrypts
    print(f"Login OK. Session token: {resp['token']}")


def cmd_upload(args):
    login_resp = request("LOGIN", username=args.username, password=args.password)
    if not login_resp["ok"]:
        print(f"Login failed: {login_resp['error']}")
        sys.exit(1)
    token = login_resp["token"]

    with open(args.filepath, "rb") as f:
        plaintext = f.read()

    sha256_plain = cu.sha256_hex(plaintext)
    aes_key, nonce, ciphertext = cu.aes_encrypt_bytes(plaintext)

    recipients = [args.username]
    if args.to:
        recipients += [r.strip() for r in args.to.split(",") if r.strip()]
    recipients = list(dict.fromkeys(recipients))  # de-dupe, preserve order

    wrapped_keys = {}
    for user in recipients:
        pk_resp = request("GET_PUBLIC_KEY", token=token, username=user)
        if not pk_resp["ok"]:
            print(f"Skipping recipient '{user}': {pk_resp['error']}")
            continue
        pubkey = cu.load_public_key_pem(pk_resp["public_key_pem"].encode())
        wrapped_keys[user] = cu.b64(cu.rsa_wrap_key(pubkey, aes_key))

    resp = request(
        "UPLOAD",
        token=token,
        filename=os.path.basename(args.filepath),
        ciphertext=cu.b64(ciphertext),
        nonce=cu.b64(nonce),
        sha256=sha256_plain,
        wrapped_keys=wrapped_keys,
    )
    if not resp["ok"]:
        print(f"Upload failed: {resp['error']}")
        sys.exit(1)
    print(f"Uploaded. file_id = {resp['file_id']}")
    print(f"Authorized recipients: {list(wrapped_keys.keys())}")
    print("The server stored only ciphertext - it cannot read this file.")


def cmd_list(args):
    login_resp = request("LOGIN", username=args.username, password=args.password)
    if not login_resp["ok"]:
        print(f"Login failed: {login_resp['error']}")
        sys.exit(1)
    resp = request("LIST_FILES", token=login_resp["token"])
    if not resp["ok"]:
        print(f"Failed: {resp['error']}")
        sys.exit(1)
    if not resp["files"]:
        print("No files visible to you.")
        return
    for fid, info in resp["files"].items():
        print(f"{fid}  owner={info['owner']:<10}  {info['filename']}")


def cmd_download(args):
    login_resp = request("LOGIN", username=args.username, password=args.password)
    if not login_resp["ok"]:
        print(f"Login failed: {login_resp['error']}")
        sys.exit(1)
    token = login_resp["token"]
    private_key = load_local_private_key(args.username, args.password)

    resp = request("DOWNLOAD", token=token, file_id=args.file_id)
    if not resp["ok"]:
        print(f"Download failed: {resp['error']}")
        sys.exit(1)

    aes_key = cu.rsa_unwrap_key(private_key, cu.unb64(resp["wrapped_key"]))
    ciphertext = cu.unb64(resp["ciphertext"])
    nonce = cu.unb64(resp["nonce"])

    try:
        plaintext = cu.aes_decrypt_bytes(aes_key, nonce, ciphertext)
    except Exception:
        print("DECRYPTION FAILED - ciphertext failed integrity check (tampered or wrong key).")
        sys.exit(1)

    if cu.sha256_hex(plaintext) != resp["sha256"]:
        print("INTEGRITY CHECK FAILED - SHA-256 mismatch. Do not trust this file.")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)
    out_path = os.path.join(args.output_dir, resp["filename"])
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"Downloaded and verified: {out_path}")
    print("AES-GCM auth tag verified (integrity) and SHA-256 matched (end-to-end confirmation).")


def cmd_logs(args):
    login_resp = request("LOGIN", username=args.username, password=args.password)
    if not login_resp["ok"]:
        print(f"Login failed: {login_resp['error']}")
        sys.exit(1)
    resp = request("GET_LOGS", token=login_resp["token"])
    if not resp["ok"]:
        print(f"Failed: {resp['error']}")
        sys.exit(1)
    print(f"Chain integrity: {'VALID' if resp['chain_valid'] else 'BROKEN at entry ' + str(resp['broken_at'])}")
    for e in resp["entries"]:
        status = "OK" if e["success"] else "FAIL"
        print(f"[{status}] {e['event']:<14} user={e['username']:<10} {e['detail']}")


def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer client")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("register")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("--role", default="user", choices=["user", "admin"])
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("login")
    p.add_argument("username")
    p.add_argument("password")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("upload")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("filepath")
    p.add_argument("--to", help="comma-separated usernames to authorize as recipients")
    p.set_defaults(func=cmd_upload)

    p = sub.add_parser("list")
    p.add_argument("username")
    p.add_argument("password")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("download")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("file_id")
    p.add_argument("output_dir")
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("logs")
    p.add_argument("username")
    p.add_argument("password")
    p.set_defaults(func=cmd_logs)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
