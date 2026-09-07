"""
auth.py
Server-side user store, password authentication, session tokens, and
role-based access control (RBAC).

IMPORTANT: the server only ever stores a salted PBKDF2 hash of each user's
password, plus their RSA PUBLIC key. It never stores or sees the private
key or the plaintext password beyond the single login request used to
compute the comparison hash in memory.
"""

import json
import os
import secrets
import time
import threading

from crypto_utils import hash_password, new_salt

USERS_FILE = os.path.join(os.path.dirname(__file__), "server_data", "users.json")
_lock = threading.Lock()


def _load():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)


def _save(users):
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


class AuthError(Exception):
    pass


class UserStore:
    def __init__(self):
        self.sessions = {}  # token -> {username, role, expires}

    # -- registration -------------------------------------------------
    def register(self, username: str, password: str, public_key_pem: str, role: str = "user"):
        with _lock:
            users = _load()
            if username in users:
                raise AuthError("username already exists")
            salt = new_salt().hex()
            pwd_hash = hash_password(password, bytes.fromhex(salt))
            users[username] = {
                "salt": salt,
                "pwd_hash": pwd_hash,
                "role": role,
                "public_key_pem": public_key_pem,
                "created_at": time.time(),
            }
            _save(users)

    # -- login ----------------------------------------------------------
    def login(self, username: str, password: str) -> str:
        users = _load()
        user = users.get(username)
        if not user:
            raise AuthError("invalid username or password")
        salt = bytes.fromhex(user["salt"])
        if hash_password(password, salt) != user["pwd_hash"]:
            raise AuthError("invalid username or password")
        token = secrets.token_hex(32)
        self.sessions[token] = {
            "username": username,
            "role": user["role"],
            "expires": time.time() + 3600,  # 1 hour session
        }
        return token

    def resolve_session(self, token: str):
        sess = self.sessions.get(token)
        if not sess:
            raise AuthError("invalid or expired session token")
        if sess["expires"] < time.time():
            del self.sessions[token]
            raise AuthError("session expired, please log in again")
        return sess  # {"username":..., "role":...}

    def get_public_key_pem(self, username: str) -> str:
        users = _load()
        user = users.get(username)
        if not user:
            raise AuthError(f"no such user: {username}")
        return user["public_key_pem"]

    def list_usernames(self):
        return list(_load().keys())

    def require_role(self, token: str, role: str):
        sess = self.resolve_session(token)
        if sess["role"] != role:
            raise AuthError(f"action requires role '{role}'")
        return sess
