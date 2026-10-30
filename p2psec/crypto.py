"""Cryptographic building blocks. Only vetted primitives from `cryptography`."""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

NONCE_LEN = 12
_RAW = serialization.Encoding.Raw
_RAW_PRIV = serialization.PrivateFormat.Raw
_RAW_PUB = serialization.PublicFormat.Raw
_NOENC = serialization.NoEncryption()


def random_key() -> bytes:
    return os.urandom(32)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def aead_encrypt(key: bytes, plaintext: bytes, aad: str) -> bytes:
    nonce = os.urandom(NONCE_LEN)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad.encode())


def aead_decrypt(key: bytes, blob: bytes, aad: str) -> bytes:
    return ChaCha20Poly1305(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad.encode())


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(ed_priv: Ed25519PrivateKey, data: bytes) -> bytes:
    return ed_priv.sign(data)


def verify(ed_pub: bytes, sig: bytes, data: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(ed_pub).verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def x25519(priv: X25519PrivateKey, peer_pub: bytes) -> bytes:
    return priv.exchange(X25519PublicKey.from_public_bytes(peer_pub))


def x_pub(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(_RAW, _RAW_PUB)


def x_priv_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(_RAW, _RAW_PRIV, _NOENC)


def fingerprint(ed_pub: bytes, x_pub_: bytes) -> str:
    h = sha256(ed_pub + x_pub_)[:16].hex()
    return " ".join(h[i:i + 4] for i in range(0, 32, 4))


@dataclass
class Identity:
    ed_priv: Ed25519PrivateKey
    x_priv: X25519PrivateKey

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate(), X25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: str, node_id: str) -> "Identity":
        """DEMO ONLY: keys anyone knowing the seed can recompute."""
        ikm = seed.encode()
        ed = hkdf(ikm, b"p2psec-demo", f"ed25519|{node_id}".encode())
        x = hkdf(ikm, b"p2psec-demo", f"x25519|{node_id}".encode())
        return cls.from_private_bytes(ed + x)

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> "Identity":
        return cls(Ed25519PrivateKey.from_private_bytes(raw[:32]),
                   X25519PrivateKey.from_private_bytes(raw[32:64]))

    def private_bytes(self) -> bytes:
        return self.ed_priv.private_bytes(_RAW, _RAW_PRIV, _NOENC) + x_priv_bytes(self.x_priv)

    def ed_pub_bytes(self) -> bytes:
        return self.ed_priv.public_key().public_bytes(_RAW, _RAW_PUB)

    def x_pub_bytes(self) -> bytes:
        return x_pub(self.x_priv)

    def fingerprint(self) -> str:
        return fingerprint(self.ed_pub_bytes(), self.x_pub_bytes())

    def sign(self, data: bytes) -> bytes:
        return sign(self.ed_priv, data)
