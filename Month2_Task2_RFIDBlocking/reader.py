"""
reader.py
Two reader roles and a backend "issuer" that can resolve a SecureTag's
anonymous, rotating response back to a real account - but only because
it holds the shared keys. This models how real contactless-card backends
identify a card from a rotating/anonymous identifier: they search their
own key database for a match, rather than the card ever announcing
"I am account #1234" over the air.

Backend:
    Holds {tag_id: key} for every issued SecureTag plus the last counter
    it has seen for each, and can identify an incoming (rotating_id,
    hmac_response) pair by searching a small resynchronization window of
    counters per known key. If nothing matches - e.g. because the
    response actually came from an attacker who doesn't hold a valid key,
    or was corrupted - identification correctly fails.

POSReader:
    A legitimate point-of-sale terminal: on a successful tag response, it
    asks the Backend to identify the card so it can authorize a payment.

SkimmerReader:
    An attacker's reader. It has NO backend access (no keys), so even if
    it successfully powers and reads a SecureTag, all it captures is an
    opaque rotating ID and an HMAC value it cannot use for anything.
"""

import crypto_utils as cu


class Backend:
    def __init__(self):
        self._registry = {}  # tag_id -> {"key": bytes, "last_counter": int}

    def register(self, tag_id: str, key: bytes):
        self._registry[tag_id] = {"key": key, "last_counter": 0}

    def identify(self, challenge: bytes, rotating_id: str, hmac_response: bytes,
                 resync_window: int = 5):
        """
        Returns tag_id if the response is authentic and recognized,
        otherwise None. Only possible because the backend holds the keys -
        an attacker intercepting the same (challenge, rotating_id,
        hmac_response) cannot replicate this without the key.
        """
        for tag_id, info in self._registry.items():
            key = info["key"]
            start = info["last_counter"] + 1
            for counter in range(start, start + resync_window):
                candidate_rotating_id = cu.hashlib.sha256(
                    f"{tag_id}:{counter}".encode()
                ).hexdigest()[:16]
                if candidate_rotating_id != rotating_id:
                    continue
                message = challenge + rotating_id.encode() + str(counter).encode()
                expected = cu.hmac_sha256(key, message)
                if cu.constant_time_eq(expected, hmac_response):
                    info["last_counter"] = counter
                    return tag_id
        return None


class POSReader:
    """A legitimate, trusted reader - e.g. a store checkout terminal."""

    def __init__(self, reader_id: str, backend: Backend):
        self.reader_id = reader_id
        self.backend = backend

    def attempt_scan(self, tag, now=None):
        challenge = cu.random_nonce()
        if hasattr(tag, "respond") and hasattr(tag, "decrypt_real_pan"):
            status, payload = tag.respond(self.reader_id, challenge, now=now)
            if status != "OK":
                return {"status": status, "identified": False}
            tag_id = self.backend.identify(challenge, payload["rotating_id"], payload["hmac_response"])
            return {
                "status": "OK",
                "identified": tag_id is not None,
                "tag_id": tag_id,
                "payload": payload,
            }
        else:  # LegacyTag - no challenge/response, just plain data
            data = tag.respond(self.reader_id)
            return {"status": "OK", "identified": True, "exposed_data": data}


class SkimmerReader:
    """An unauthorized/attacker reader - no key material, no backend access."""

    def __init__(self, reader_id: str = "unknown-skimmer"):
        self.reader_id = reader_id
        self.captured = []  # whatever raw data it manages to intercept

    def attempt_scan(self, tag, now=None):
        challenge = cu.random_nonce()
        if hasattr(tag, "respond") and hasattr(tag, "decrypt_real_pan"):
            status, payload = tag.respond(self.reader_id, challenge, now=now)
            if status != "OK":
                return {"status": status, "exposed_data": None}
            # The skimmer can capture the rotating_id/hmac, but has no key
            # and no backend - it is cryptographically unable to turn this
            # into a usable account number.
            self.captured.append(payload)
            return {"status": "OK", "exposed_data": None, "captured_opaque": payload}
        else:
            data = tag.respond(self.reader_id)
            self.captured.append(data)
            return {"status": "OK", "exposed_data": data}
