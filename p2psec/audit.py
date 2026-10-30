"""Append-only, hash-chained, Ed25519-signed audit log, plus peer log anchors."""
from __future__ import annotations

import json
import sqlite3

from . import crypto, db
from .crypto import Identity

GENESIS = "0" * 64


def _entry_hash(entry: dict) -> str:
    body = {k: entry[k] for k in ("seq", "ts", "actor_fpr", "event_type", "subject", "details", "prev_hash")}
    return crypto.sha256(crypto.canonical_json(body) + bytes.fromhex(entry["prev_hash"])).hex()


class AuditLog:
    def __init__(self, conn: sqlite3.Connection, identity: Identity):
        self.conn = conn
        self.identity = identity

    def head(self) -> tuple[int, str]:
        r = self.conn.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        return (r[0], r[1]) if r else (0, GENESIS)

    def append(self, event_type: str, subject: dict, details: dict | None = None,
               ts: float | None = None, actor_fpr: str | None = None) -> dict:
        seq, prev = self.head()
        entry = {"seq": seq + 1, "ts": ts if ts is not None else db.now(),
                 "actor_fpr": actor_fpr or self.identity.fingerprint(), "event_type": event_type,
                 "subject": json.dumps(subject, sort_keys=True),
                 "details": json.dumps(details or {}, sort_keys=True), "prev_hash": prev}
        entry["hash"] = _entry_hash(entry)
        entry["sig"] = self.identity.sign(bytes.fromhex(entry["hash"]))
        db.insert(self.conn, "audit", entry)
        return entry

    def verify(self) -> tuple[bool, int | None]:
        expected_seq, prev = 1, GENESIS
        ed_pub = self.identity.ed_pub_bytes()
        for e in db.rows(self.conn, "SELECT * FROM audit ORDER BY seq"):
            if (e["seq"] != expected_seq or e["prev_hash"] != prev or _entry_hash(e) != e["hash"]
                    or not crypto.verify(ed_pub, e["sig"], bytes.fromhex(e["hash"]))):
                return False, e["seq"]
            expected_seq, prev = e["seq"] + 1, e["hash"]
        return True, None

    def record_anchor(self, peer_fpr: str, seq: int, hash_: str) -> bool:
        """Remember the latest (seq, head) a peer showed us. Regression or a fork means
        that peer rewrote its log; raise an alert and keep the older anchor."""
        old = db.row(self.conn, "SELECT * FROM anchors WHERE peer_fpr=?", (peer_fpr,))
        if old and (seq < old["seq"] or (seq == old["seq"] and hash_ != old["hash"])):
            db.add_alert(self.conn, "LOG_ANCHOR_MISMATCH",
                         f"Peer {peer_fpr} presented log head #{seq} after #{old['seq']}; "
                         "its audit log may have been rewritten or truncated.", peer_fpr)
            return False
        db.insert(self.conn, "anchors", {"peer_fpr": peer_fpr, "seq": seq, "hash": hash_, "ts": db.now()},
                  replace=True)
        return True
