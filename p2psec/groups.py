"""Signed, hash-linked group documents.

Rules (spec §7.2):
- every version links to the previous one by hash; nodes only accept extensions of their head;
- a version must be signed by custodian(s) of the *previous* version;
- changing the custodian list needs a majority of the previous custodians;
- two different versions with the same parent are a fork: refused, never "highest wins";
- v1 must be signed by a key the receiver has pinned through pairing.
"""
from __future__ import annotations

import base64
import copy
import json
import sqlite3
from typing import Callable

from . import crypto, db
from .crypto import Identity


class GroupError(Exception):
    def __init__(self, code: str, message: str = ""):
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


def person(name: str, ident: Identity, title: str = "") -> dict:
    return {"fpr": ident.fingerprint(), "name": name, "title": title,
            "ed_pub": _b(ident.ed_pub_bytes()), "x_pub": _b(ident.x_pub_bytes())}


def person_from_contact(contact: dict) -> dict:
    return {"fpr": contact["fpr"], "name": contact["name"], "title": contact.get("title") or "",
            "ed_pub": _b(contact["ed_pub"]), "x_pub": _b(contact["x_pub"])}


def doc_hash(doc: dict) -> str:
    body = {k: v for k, v in doc.items() if k != "sigs"}
    return crypto.sha256(crypto.canonical_json(body)).hex()


def _sign(doc: dict, ident: Identity) -> dict:
    sig = ident.sign(bytes.fromhex(doc_hash(doc)))
    doc["sigs"] = [s for s in doc.get("sigs", []) if s["fpr"] != ident.fingerprint()]
    doc["sigs"].append({"fpr": ident.fingerprint(), "sig": _b(sig)})
    return doc


def make_genesis(group_id: str, name: str, description: str, custodians: list[dict], members: list[dict],
                 policy: dict, credentials: list[dict], signers: list[Identity]) -> dict:
    doc = {"group_id": group_id, "name": name, "description": description, "version": 1, "prev_hash": None,
           "custodians": custodians, "members": members, "policy": policy, "credentials": credentials,
           "sigs": []}
    for s in signers:
        _sign(doc, s)
    return doc


def make_next(prev: dict, changes: dict, signers: list[Identity]) -> dict:
    doc = copy.deepcopy(prev)
    doc.update(copy.deepcopy(changes))
    doc["version"] = prev["version"] + 1
    doc["prev_hash"] = doc_hash(prev)
    doc["sigs"] = []
    for s in signers:
        _sign(doc, s)
    return doc


def cosign(doc: dict, ident: Identity) -> dict:
    return _sign(copy.deepcopy(doc), ident)


def is_member(doc: dict, fpr: str) -> bool:
    return any(p["fpr"] == fpr for p in doc["members"] + doc["custodians"])


def is_custodian(doc: dict, fpr: str) -> bool:
    return any(p["fpr"] == fpr for p in doc["custodians"])


def _valid_signers(doc: dict, keys: dict[str, bytes]) -> set[str]:
    h = bytes.fromhex(doc_hash(doc))
    ok = set()
    for s in doc.get("sigs", []):
        pub = keys.get(s["fpr"])
        if pub is None:
            continue
        if not crypto.verify(pub, base64.b64decode(s["sig"]), h):
            raise GroupError("BAD_SIG", f"signature by {s['fpr']} does not verify")
        ok.add(s["fpr"])
    return ok


def _custodian_keys(doc: dict) -> dict[str, bytes]:
    keys = {}
    for c in doc["custodians"]:
        ed, x = base64.b64decode(c["ed_pub"]), base64.b64decode(c["x_pub"])
        if crypto.fingerprint(ed, x) != c["fpr"]:
            raise GroupError("BAD_SIG", "custodian key does not match fingerprint")
        keys[c["fpr"]] = ed
    return keys


CRITICALITIES = ("Critical", "High", "Medium", "Low")


def _check_schema(doc) -> None:
    def bad(why):
        raise GroupError("BAD_SCHEMA", why)

    def text(v, n, field, empty=True):
        if not isinstance(v, str) or len(v) > n or (not empty and not v):
            bad(field)

    if not isinstance(doc, dict):
        bad("document")
    text(doc.get("group_id"), 64, "group_id", empty=False)
    text(doc.get("name"), 100, "name", empty=False)
    text(doc.get("description"), 500, "description")
    if not isinstance(doc.get("version"), int) or isinstance(doc.get("version"), bool) or doc["version"] < 1:
        bad("version")
    if doc.get("prev_hash") is not None:
        text(doc["prev_hash"], 64, "prev_hash")
    for key, lo, hi in (("custodians", 1, 3), ("members", 0, 500)):
        people = doc.get(key)
        if not isinstance(people, list) or not lo <= len(people) <= hi:
            bad(key)
        for p in people:
            if not isinstance(p, dict):
                bad(key)
            for f in ("fpr", "name", "ed_pub", "x_pub"):
                text(p.get(f), 100, f"{key}.{f}", empty=False)
            text(p.get("title", ""), 100, f"{key}.title")
    pol = doc.get("policy")
    if not isinstance(pol, dict):
        bad("policy")
    for f in ("auto_approve_members", "allow_non_member_requests"):
        if not isinstance(pol.get(f), bool):
            bad(f"policy.{f}")
    for f in ("max_lease_minutes", "default_lease_minutes"):
        v = pol.get(f)
        if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 1440:
            bad(f"policy.{f}")
    creds = doc.get("credentials")
    if not isinstance(creds, list) or len(creds) > 500:
        bad("credentials")
    for c in creds:
        if not isinstance(c, dict):
            bad("credentials")
        text(c.get("cred_id"), 64, "credentials.cred_id", empty=False)
        text(c.get("name"), 200, "credentials.name", empty=False)
        for f in ("url", "username", "account_type"):
            text(c.get(f, ""), 500, f"credentials.{f}")
        if c.get("criticality") not in CRITICALITIES:
            bad("credentials.criticality")
    if not isinstance(doc.get("sigs"), list) or not all(
            isinstance(x, dict) and isinstance(x.get("fpr"), str) and isinstance(x.get("sig"), str) for x in doc["sigs"]):
        bad("sigs")


def validate_extension(head: dict | None, new: dict, my_fpr: str,
                       pinned: Callable[[str], bytes | None]) -> str:
    """Return 'accept' | 'duplicate' | 'stale', or raise GroupError."""
    _check_schema(new)
    if head is None:
        if new.get("version") != 1 or new.get("prev_hash") is not None:
            raise GroupError("NOT_EXTENSION", "need the group's history from v1")
        keys = {s["fpr"]: pinned(s["fpr"]) for s in new.get("sigs", []) if pinned(s["fpr"])}
        if not keys:
            raise GroupError("GENESIS_UNTRUSTED", "v1 is not signed by any paired contact")
        signers = _valid_signers(new, keys)
        if not signers & set(_custodian_keys(new)):
            raise GroupError("NOT_CUSTODIAN", "v1 signer is not a custodian")
        if my_fpr is not None and not is_member(new, my_fpr):
            raise GroupError("NOT_LISTED", "this node is not in the group")
        return "accept"

    if new["group_id"] != head["group_id"]:
        raise GroupError("NOT_EXTENSION", "different group")
    if new["version"] < head["version"]:
        return "stale"
    if new["version"] == head["version"]:
        if doc_hash(new) == doc_hash(head):
            return "duplicate"
        raise GroupError("FORK", "a different version with the same number already exists")
    if new["version"] > head["version"] + 1:
        raise GroupError("NOT_EXTENSION", "missing intermediate versions")
    if new.get("prev_hash") != doc_hash(head):
        raise GroupError("FORK", "does not extend the current version")

    prev_custodians = _custodian_keys(head)
    for s in new.get("sigs", []):
        if s["fpr"] not in prev_custodians:
            raise GroupError("NOT_CUSTODIAN", f"{s['fpr']} is not a custodian of v{head['version']}")
    signers = _valid_signers(new, prev_custodians)
    if not signers:
        raise GroupError("NOT_CUSTODIAN", "unsigned")
    _custodian_keys(new)
    if {c["fpr"] for c in new["custodians"]} != set(prev_custodians):
        if len(signers) < len(prev_custodians) // 2 + 1:
            raise GroupError("NEED_MAJORITY", "custodian changes need a majority of current custodians")
    return "accept"


# --- storage -------------------------------------------------------------

def head_doc(conn: sqlite3.Connection, group_id: str) -> dict | None:
    r = db.row(conn, "SELECT doc FROM group_docs WHERE group_id=? ORDER BY version DESC LIMIT 1", (group_id,))
    return json.loads(r["doc"]) if r else None


def chain(conn: sqlite3.Connection, group_id: str) -> list[dict]:
    return [json.loads(r["doc"]) for r in
            db.rows(conn, "SELECT doc FROM group_docs WHERE group_id=? ORDER BY version", (group_id,))]


def store(conn: sqlite3.Connection, doc: dict) -> None:
    db.insert(conn, "group_docs", {"group_id": doc["group_id"], "version": doc["version"],
                                   "doc": json.dumps(doc), "hash": doc_hash(doc)}, replace=True)


def all_heads(conn: sqlite3.Connection) -> list[dict]:
    ids = [r["group_id"] for r in db.rows(conn, "SELECT DISTINCT group_id FROM group_docs")]
    return [head_doc(conn, g) for g in ids]
