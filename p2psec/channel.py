"""Authenticated session channel: Noise_KK_25519_ChaChaPoly_SHA256 with pinned static keys.

The initiator first sends a cleartext hello naming its fingerprint so the responder
can pick the pinned key; KK then proves both sides hold the pinned private keys.
Every application message is wrapped in an envelope {msg_id, ts, type, body, anchor}
and checked against a replay cache.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
import time
import uuid
from typing import Callable

from noise.connection import Keypair, NoiseConnection

from . import crypto, db, framing
from .crypto import Identity

PROTOCOL = b"Noise_KK_25519_ChaChaPoly_SHA256"
PROLOGUE = b"p2psec/1"
CHUNK = 65000          # Noise messages are capped at 65535 bytes
SKEW = 300
REPLAY_WINDOW = 24 * 3600


class ChannelError(Exception):
    pass


class ReplayGuard:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def check(self, msg_id: str, ts: float, now: float | None = None) -> None:
        now = now or time.time()
        if abs(now - float(ts)) > SKEW:
            raise ChannelError("timestamp skew too large")
        try:
            self.conn.execute("INSERT INTO seen_msgs (msg_id, ts) VALUES (?, ?)", (str(msg_id), now))
        except sqlite3.IntegrityError:
            raise ChannelError("replayed message") from None
        self.conn.execute("DELETE FROM seen_msgs WHERE ts < ?", (now - REPLAY_WINDOW,))


def _noise(identity: Identity, peer_x_pub: bytes, initiator: bool) -> NoiseConnection:
    n = NoiseConnection.from_name(PROTOCOL)
    n.set_as_initiator() if initiator else n.set_as_responder()
    n.set_prologue(PROLOGUE)
    n.set_keypair_from_private_bytes(Keypair.STATIC, crypto.x_priv_bytes(identity.x_priv))
    n.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, peer_x_pub)
    n.start_handshake()
    return n


class Channel:
    def __init__(self, reader, writer, noise: NoiseConnection, peer_fpr: str, guard: ReplayGuard,
                 anchor: Callable[[], dict] | None = None):
        self.reader, self.writer, self.noise = reader, writer, noise
        self.peer_fpr = peer_fpr
        self.guard = guard
        self.anchor = anchor or (lambda: {})

    async def send(self, msg_type: str, body: dict) -> None:
        env = {"msg_id": str(uuid.uuid4()), "ts": time.time(), "type": msg_type,
               "body": body, "anchor": self.anchor()}
        data = json.dumps(env).encode()
        chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
        for i, chunk in enumerate(chunks):
            more = b"\x01" if i < len(chunks) - 1 else b"\x00"
            await framing.send_frame(self.writer, self.noise.encrypt(more + chunk))

    async def recv(self) -> tuple[str, dict, dict]:
        data = b""
        while True:
            frame = await framing.recv_frame(self.reader)
            try:
                plain = self.noise.decrypt(frame)
            except Exception:
                raise ChannelError("decryption failed") from None
            data += plain[1:]
            if len(data) > framing.MAX_FRAME * 4:
                raise ChannelError("message too large")
            if plain[:1] == b"\x00":
                break
        try:
            env = json.loads(data)
            msg_type, body = str(env["type"]), env["body"]
        except (ValueError, KeyError, TypeError):
            raise ChannelError("bad envelope") from None
        if not isinstance(body, dict):
            raise ChannelError("bad envelope")
        self.guard.check(env.get("msg_id"), env.get("ts", 0))
        return msg_type, body, env

    def close(self) -> None:
        self.writer.close()


async def open_channel(reader, writer, identity: Identity, peer: dict, guard: ReplayGuard,
                       anchor=None) -> Channel:
    """peer: pinned contact with ed_pub and x_pub."""
    await framing.send_json(writer, {"t": "hello", "v": 1, "kind": "session", "fpr": identity.fingerprint()})
    noise = _noise(identity, peer["x_pub"], initiator=True)
    await framing.send_frame(writer, noise.write_message())
    try:
        noise.read_message(await framing.recv_frame(reader))
    except framing.FrameError:
        raise ChannelError("handshake failed: peer closed the connection") from None
    except Exception:
        raise ChannelError("handshake failed: peer key does not match pinned key") from None
    return Channel(reader, writer, noise, crypto.fingerprint(peer["ed_pub"], peer["x_pub"]), guard, anchor)


async def accept_channel(reader, writer, identity: Identity, hello: dict,
                         lookup: Callable[[str], dict | None], guard: ReplayGuard, anchor=None) -> Channel:
    contact = lookup(str(hello.get("fpr", "")))
    if not contact:
        raise ChannelError("unknown peer")
    noise = _noise(identity, contact["x_pub"], initiator=False)
    try:
        noise.read_message(await asyncio.wait_for(framing.recv_frame(reader), 10))
    except (framing.FrameError, asyncio.TimeoutError):
        raise ChannelError("handshake failed") from None
    except Exception:
        raise ChannelError("handshake failed: initiator key does not match pinned key") from None
    await framing.send_frame(writer, noise.write_message())
    peer_fpr = str(hello["fpr"])
    if "ed_pub" in contact and crypto.fingerprint(contact["ed_pub"], contact["x_pub"]) != peer_fpr:
        raise ChannelError("fingerprint mismatch")
    return Channel(reader, writer, noise, peer_fpr, guard, anchor)
