"""
server.py
Secure File Transfer - server.

The server:
  - Terminates a TLS connection per client (transport security).
  - Authenticates users (PBKDF2 password hash comparison) and issues
    session tokens (RBAC: 'user' / 'admin').
  - Stores and relays END-TO-END ENCRYPTED file blobs. It NEVER sees
    plaintext file contents and NEVER has access to any private key -
    it is cryptographically incapable of decrypting what it stores.
  - Enforces access control: a file may only be downloaded by its owner
    or by usernames explicitly listed as authorized recipients at
    upload time (checked against the wrapped-key map).
  - Writes a tamper-evident, hash-chained audit log entry for every
    security-relevant event (register, login, upload, download, access
    denied, share).

Wire protocol: each message is a 4-byte big-endian length prefix followed
by that many bytes of UTF-8 JSON. Binary data (ciphertext, wrapped keys)
is base64-encoded inside the JSON for simplicity.
"""

import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import uuid

import auth
import audit_log
from crypto_utils import sha256_hex

HOST = "0.0.0.0"
PORT = 9443

SERVER_DATA = os.path.join(os.path.dirname(__file__), "server_data")
FILES_DIR = os.path.join(SERVER_DATA, "files")
FILES_META = os.path.join(SERVER_DATA, "files.json")
CERT_FILE = os.path.join(SERVER_DATA, "server.crt")
KEY_FILE = os.path.join(SERVER_DATA, "server.key")

_meta_lock = threading.Lock()
user_store = auth.UserStore()


# ---------------------------------------------------------------------------
# Framed JSON send/recv
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# File metadata store
# ---------------------------------------------------------------------------

def _load_meta():
    if not os.path.exists(FILES_META):
        return {}
    with open(FILES_META, "r") as f:
        return json.load(f)


def _save_meta(meta):
    os.makedirs(SERVER_DATA, exist_ok=True)
    with open(FILES_META, "w") as f:
        json.dump(meta, f, indent=2)


# ---------------------------------------------------------------------------
# Request handlers
# ---------------------------------------------------------------------------

def handle_register(req, addr):
    username = req["username"]
    password = req["password"]
    pubkey_pem = req["public_key_pem"]
    role = req.get("role", "user")
    try:
        user_store.register(username, password, pubkey_pem, role)
        audit_log.log_event("REGISTER", username, True, ip=addr[0])
        return {"ok": True}
    except auth.AuthError as e:
        audit_log.log_event("REGISTER", username, False, detail=str(e), ip=addr[0])
        return {"ok": False, "error": str(e)}


def handle_login(req, addr):
    username = req["username"]
    password = req["password"]
    try:
        token = user_store.login(username, password)
        audit_log.log_event("LOGIN", username, True, ip=addr[0])
        return {"ok": True, "token": token}
    except auth.AuthError as e:
        audit_log.log_event("LOGIN", username, False, detail=str(e), ip=addr[0])
        return {"ok": False, "error": str(e)}


def handle_get_public_key(req, addr):
    try:
        sess = user_store.resolve_session(req["token"])
        pem = user_store.get_public_key_pem(req["username"])
        return {"ok": True, "public_key_pem": pem}
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}


def handle_list_users(req, addr):
    try:
        user_store.resolve_session(req["token"])
        return {"ok": True, "users": user_store.list_usernames()}
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}


def handle_upload(req, addr):
    try:
        sess = user_store.resolve_session(req["token"])
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}

    owner = sess["username"]
    filename = req["filename"]
    ciphertext_b64 = req["ciphertext"]
    nonce_b64 = req["nonce"]
    sha256_plain = req["sha256"]
    wrapped_keys = req["wrapped_keys"]  # {username: wrapped_key_b64}

    file_id = uuid.uuid4().hex
    os.makedirs(FILES_DIR, exist_ok=True)
    blob_path = os.path.join(FILES_DIR, file_id + ".bin")

    # Server stores raw base64 ciphertext exactly as received - it never
    # decodes/decrypts it, since it has no key capable of doing so.
    with open(blob_path, "w") as f:
        f.write(ciphertext_b64)

    with _meta_lock:
        meta = _load_meta()
        meta[file_id] = {
            "owner": owner,
            "filename": filename,
            "nonce": nonce_b64,
            "sha256": sha256_plain,
            "wrapped_keys": wrapped_keys,  # only for owner + authorized recipients
            "uploaded_at": time.time(),
        }
        _save_meta(meta)

    audit_log.log_event(
        "UPLOAD", owner, True,
        detail=f"file_id={file_id} filename={filename} recipients={list(wrapped_keys.keys())}",
        ip=addr[0],
    )
    return {"ok": True, "file_id": file_id}


def handle_list_files(req, addr):
    try:
        sess = user_store.resolve_session(req["token"])
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}
    username = sess["username"]
    meta = _load_meta()
    visible = {
        fid: {"filename": m["filename"], "owner": m["owner"], "uploaded_at": m["uploaded_at"]}
        for fid, m in meta.items()
        if username == m["owner"] or username in m["wrapped_keys"]
    }
    return {"ok": True, "files": visible}


def handle_download(req, addr):
    try:
        sess = user_store.resolve_session(req["token"])
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}

    username = sess["username"]
    file_id = req["file_id"]
    meta = _load_meta()
    entry = meta.get(file_id)

    if not entry:
        audit_log.log_event("DOWNLOAD", username, False, detail=f"file_id={file_id} not found", ip=addr[0])
        return {"ok": False, "error": "file not found"}

    # --- ACCESS CONTROL CHECK ---
    if username != entry["owner"] and username not in entry["wrapped_keys"]:
        audit_log.log_event(
            "ACCESS_DENIED", username, False,
            detail=f"file_id={file_id} owner={entry['owner']}", ip=addr[0],
        )
        return {"ok": False, "error": "access denied"}

    blob_path = os.path.join(FILES_DIR, file_id + ".bin")
    with open(blob_path, "r") as f:
        ciphertext_b64 = f.read()

    wrapped_key_b64 = entry["wrapped_keys"][username]

    audit_log.log_event(
        "DOWNLOAD", username, True,
        detail=f"file_id={file_id} filename={entry['filename']}", ip=addr[0],
    )
    return {
        "ok": True,
        "filename": entry["filename"],
        "ciphertext": ciphertext_b64,
        "nonce": entry["nonce"],
        "sha256": entry["sha256"],
        "wrapped_key": wrapped_key_b64,
    }


def handle_get_logs(req, addr):
    try:
        sess = user_store.require_role(req["token"], "admin")
    except auth.AuthError as e:
        return {"ok": False, "error": str(e)}
    is_valid, broken_at = audit_log.verify_chain()
    return {"ok": True, "entries": audit_log.read_all(), "chain_valid": is_valid, "broken_at": broken_at}


HANDLERS = {
    "REGISTER": handle_register,
    "LOGIN": handle_login,
    "GET_PUBLIC_KEY": handle_get_public_key,
    "LIST_USERS": handle_list_users,
    "UPLOAD": handle_upload,
    "LIST_FILES": handle_list_files,
    "DOWNLOAD": handle_download,
    "GET_LOGS": handle_get_logs,
}


def client_thread(raw_conn, addr, ctx):
    conn = None
    try:
        try:
            conn = ctx.wrap_socket(raw_conn, server_side=True)
        except ssl.SSLError as e:
            print(f"TLS handshake failed with {addr}: {e}")
            return
        while True:
            try:
                req = recv_msg(conn)
            except (ConnectionError, json.JSONDecodeError, struct.error):
                break
            cmd = req.get("cmd")
            handler = HANDLERS.get(cmd)
            if not handler:
                send_msg(conn, {"ok": False, "error": f"unknown command: {cmd}"})
                continue
            try:
                resp = handler(req, addr)
            except Exception as e:  # never leak stack traces to the client
                resp = {"ok": False, "error": "internal server error"}
                audit_log.log_event("SERVER_ERROR", "-", False, detail=f"{cmd}: {e}", ip=addr[0])
            send_msg(conn, resp)
    finally:
        if conn is not None:
            conn.close()
        else:
            raw_conn.close()


def main():
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("TLS certificate not found. Run: python gen_cert.py")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"Secure File Transfer server listening on {HOST}:{PORT} (TLS)")
        while True:
            raw_conn, addr = sock.accept()
            # TLS handshake happens inside the thread, not in the accept
            # loop, so one bad/slow handshake can never block or crash
            # the server's ability to accept other connections.
            t = threading.Thread(target=client_thread, args=(raw_conn, addr, ctx), daemon=True)
            t.start()


if __name__ == "__main__":
    main()
