"""Vault: master password -> Argon2id KEK -> two wrapped key tiers.

personal tier: personal credential secrets and received checkouts. Wiped on soft lock.
service tier:  node private keys and custodian group secrets. Survives soft lock so the
               node can keep serving peers; wiped only on full lock / process exit.
"""
from __future__ import annotations

import base64
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag

from . import crypto

DEFAULT_PARAMS = {"t": 3, "m": 65536, "p": 2}
TIERS = ("personal", "service")


class BadPassword(Exception):
    pass


class Locked(Exception):
    pass


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    return base64.b64decode(s)


def _kek(password: str, salt: bytes, params: dict) -> bytes:
    return hash_secret_raw(password.encode(), salt, time_cost=params["t"], memory_cost=params["m"],
                           parallelism=params["p"], hash_len=32, type=Type.ID)


def _unwrap(header: dict, password: str) -> dict[str, bytes]:
    kek = _kek(password, _unb64(header["salt"]), header["params"])
    try:
        return {t: crypto.aead_decrypt(kek, _unb64(header["wrapped"][t]), f"vault|{t}") for t in TIERS}
    except InvalidTag:
        raise BadPassword() from None


def _header(password: str, keys: dict[str, bytes], params: dict) -> dict:
    salt = os.urandom(16)
    kek = _kek(password, salt, params)
    return {"salt": _b64(salt), "params": dict(params),
            "wrapped": {t: _b64(crypto.aead_encrypt(kek, keys[t], f"vault|{t}")) for t in TIERS}}


class Vault:
    def __init__(self, keys: dict[str, bytes]):
        self._keys: dict[str, bytes | None] = dict(keys)

    @classmethod
    def create(cls, password: str, params: dict | None = None) -> tuple["Vault", dict]:
        keys = {t: crypto.random_key() for t in TIERS}
        return cls(keys), _header(password, keys, params or DEFAULT_PARAMS)

    @classmethod
    def unlock(cls, header: dict, password: str) -> "Vault":
        return cls(_unwrap(header, password))

    def unlock_personal(self, header: dict, password: str) -> None:
        keys = _unwrap(header, password)
        self._keys["personal"] = keys["personal"]
        if self._keys["service"] is None:
            self._keys["service"] = keys["service"]

    @property
    def personal_unlocked(self) -> bool:
        return self._keys["personal"] is not None

    @property
    def service_unlocked(self) -> bool:
        return self._keys["service"] is not None

    def soft_lock(self) -> None:
        self._keys["personal"] = None

    def full_lock(self) -> None:
        self._keys = {t: None for t in TIERS}

    def _key(self, tier: str) -> bytes:
        key = self._keys[tier]
        if key is None:
            raise Locked(tier)
        return key

    def enc(self, tier: str, record_type: str, record_id: str, plaintext: bytes) -> bytes:
        return crypto.aead_encrypt(self._key(tier), plaintext, f"{record_type}|{record_id}")

    def dec(self, tier: str, record_type: str, record_id: str, blob: bytes) -> bytes:
        return crypto.aead_decrypt(self._key(tier), blob, f"{record_type}|{record_id}")

    def rewrap(self, header: dict, old: str, new: str) -> dict:
        keys = _unwrap(header, old)
        return _header(new, keys, header["params"])
