"""MITM-resistant pairing: commit-before-reveal ephemeral exchange + 6-digit SAS.

  A -> B  pair1: commit = H(eA || nA || A.ed || A.x)
  B -> A  pair2: eB, nB, B.ed, B.x            (B fixes its keys before seeing A's)
  A -> B  pair3: eA, nA, A.ed, A.x, card_A    (B checks commit)
  B -> A  pair4: card_B
  both:   pair_confirm (encrypted yes/no after the humans compare SAS)

A man in the middle runs one session with each side. Because each side's
contribution is fixed before it sees the other's, the attacker cannot steer the
two SAS values to collide; it gets a single 1-in-10^6 guess per attempt.
Pure state machines: no I/O, so they can be tested and driven by any transport.
"""
from __future__ import annotations

import base64
import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from . import crypto
from .crypto import Identity

PROTO_VERSION = 1


class PairingError(Exception):
    pass


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


def _u(s) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except Exception:
        raise PairingError("bad encoding") from None


def _commit(e: bytes, n: bytes, ed: bytes, x: bytes) -> str:
    return crypto.sha256(e + n + ed + x).hex()


class _Side:
    role = ""

    def __init__(self, identity: Identity, card: dict):
        self.identity = identity
        self.card = card
        self.eph = X25519PrivateKey.generate()
        self.nonce = os.urandom(16)
        self.sas: str | None = None
        self.peer_card: dict | None = None
        self.peer_ed: bytes | None = None
        self.peer_x: bytes | None = None
        self._k: bytes | None = None
        self._th: bytes | None = None

    @property
    def peer_identity_fpr(self) -> str:
        return crypto.fingerprint(self.peer_ed, self.peer_x)

    def _mine(self) -> dict:
        return {"e": _b(crypto.x_pub(self.eph)), "n": _b(self.nonce),
                "ed": _b(self.identity.ed_pub_bytes()), "x": _b(self.identity.x_pub_bytes())}

    def _derive(self, commit: str, a: dict, b: dict, peer_e: bytes) -> None:
        transcript = {"v": PROTO_VERSION, "commit": commit, "a": a, "b": b}
        self._th = crypto.sha256(crypto.canonical_json(transcript))
        self._k = crypto.hkdf(crypto.x25519(self.eph, peer_e), self._th, b"p2psec-pair-key")
        sas_bytes = crypto.hkdf(self._k, None, b"p2psec-sas", 8)
        self.sas = str(int.from_bytes(sas_bytes, "big") % 1_000_000).zfill(6)

    def _seal_card(self) -> str:
        card = dict(self.card, ed_pub=_b(self.identity.ed_pub_bytes()),
                    x_pub=_b(self.identity.x_pub_bytes()))
        sig = self.identity.sign(self._th + self.role.encode())
        payload = crypto.canonical_json({"card": card, "sig": _b(sig)})
        return _b(crypto.aead_encrypt(self._k, payload, f"pair-card|{self.role}"))

    def _open_card(self, blob: str, peer_role: str) -> None:
        try:
            payload = json.loads(crypto.aead_decrypt(self._k, _u(blob), f"pair-card|{peer_role}"))
        except (InvalidTag, ValueError):
            raise PairingError("card decryption failed") from None
        card = payload["card"]
        if _u(card["ed_pub"]) != self.peer_ed or _u(card["x_pub"]) != self.peer_x:
            raise PairingError("card keys do not match handshake")
        if not crypto.verify(self.peer_ed, _u(payload["sig"]), self._th + peer_role.encode()):
            raise PairingError("card signature invalid")
        self.peer_card = card

    def confirm(self, ok: bool) -> dict:
        body = crypto.canonical_json({"ok": bool(ok)})
        return {"t": "pair_confirm", "ct": _b(crypto.aead_encrypt(self._k, body, f"pair-ok|{self.role}"))}

    def on_confirm(self, msg: dict) -> bool:
        peer_role = "B" if self.role == "A" else "A"
        try:
            return bool(json.loads(crypto.aead_decrypt(self._k, _u(msg["ct"]), f"pair-ok|{peer_role}"))["ok"])
        except (InvalidTag, ValueError, KeyError):
            raise PairingError("bad confirmation") from None


class PairingInitiator(_Side):
    role = "A"

    def msg1(self) -> dict:
        m = self._mine()
        self._commitment = _commit(*(_u(m[k]) for k in ("e", "n", "ed", "x")))
        return {"t": "pair1", "v": PROTO_VERSION, "commit": self._commitment}

    def on_msg2(self, msg: dict) -> dict:
        if msg.get("t") != "pair2":
            raise PairingError("unexpected message")
        b = {k: msg[k] for k in ("e", "n", "ed", "x")}
        self.peer_ed, self.peer_x = _u(b["ed"]), _u(b["x"])
        a = self._mine()
        self._derive(self._commitment, a, b, _u(b["e"]))
        return {"t": "pair3", **a, "card": self._seal_card()}

    def on_msg4(self, msg: dict) -> None:
        if msg.get("t") != "pair4":
            raise PairingError("unexpected message")
        self._open_card(msg["card"], "B")


class PairingResponder(_Side):
    role = "B"

    def on_msg1(self, msg: dict) -> dict:
        if msg.get("t") != "pair1" or msg.get("v") != PROTO_VERSION:
            raise PairingError("unsupported protocol")
        self._commitment = str(msg["commit"])
        self._b_fields = self._mine()
        return {"t": "pair2", **self._b_fields}

    def on_msg3(self, msg: dict) -> dict:
        if msg.get("t") != "pair3":
            raise PairingError("unexpected message")
        a = {k: msg[k] for k in ("e", "n", "ed", "x")}
        if _commit(*(_u(a[k]) for k in ("e", "n", "ed", "x"))) != self._commitment:
            raise PairingError("commit mismatch: possible man-in-the-middle")
        self.peer_ed, self.peer_x = _u(a["ed"]), _u(a["x"])
        self._derive(self._commitment, a, self._b_fields, _u(a["e"]))
        self._open_card(msg["card"], "A")
        return {"t": "pair4", "card": self._seal_card()}
