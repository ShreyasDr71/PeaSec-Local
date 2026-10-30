"""Policy and state engine: requests, checkouts (leases), receipts, rotation, custodian sync.

The engine never does I/O. Every action returns a list of `Out` messages for the peer
layer to deliver. `handle()` is the single entry point for inbound peer messages; the
`sender_fpr` it receives always comes from the authenticated channel, never the body.
"""
from __future__ import annotations

import base64
import json
import sqlite3
from dataclasses import dataclass, field

from . import crypto, db, groups
from .audit import AuditLog
from .crypto import Identity
from .vault import Vault

DAY = 86400
ROTATION_WINDOW_DAYS = 30
MAX_MINUTES = 24 * 60
TERMINAL = ("checked_in", "expired", "revoked")
CRITICALITIES = ("Critical", "High", "Medium", "Low")
ACCOUNT_TYPES = ("Domain Admin", "Local Admin", "Root", "Service Account", "Network Device",
                 "Cloud Root", "Database", "Application")
IDENTITY_FIELDS = ("requester_fpr", "sender_fpr", "from_fpr", "signer_fpr")


class EngineError(Exception):
    pass


@dataclass
class Out:
    to: list[str]
    type: str
    body: dict
    any: bool = False          # deliver to the first reachable target only


def decide(member: bool, policy: dict, minutes: int, criticality: str) -> str:
    if not member:
        return "manual" if policy.get("allow_non_member_requests", True) else "deny"
    if criticality == "Critical":
        return "manual"
    if policy.get("auto_approve_members") and minutes <= policy.get("max_lease_minutes", 0):
        return "auto"
    return "manual"


def _b(x: bytes) -> str:
    return base64.b64encode(x).decode()


class Engine:
    def __init__(self, conn: sqlite3.Connection, vault: Vault, audit: AuditLog, identity: Identity,
                 profile: dict):
        self.conn, self.vault, self.audit, self.identity, self.profile = conn, vault, audit, identity, profile
        self.fpr = identity.fingerprint()

    # --- contacts ---------------------------------------------------------

    def add_contact(self, c: dict) -> None:
        db.insert(self.conn, "contacts", {"fpr": c["fpr"], "name": c["name"], "title": c.get("title", ""),
                                          "dept": c.get("dept", ""), "ed_pub": c["ed_pub"], "x_pub": c["x_pub"],
                                          "addr": c.get("addr"), "last_seen": c.get("last_seen"),
                                          "paired_at": c.get("paired_at", db.now()),
                                          "demo": int(bool(c.get("demo")))}, replace=True)

    def contact(self, fpr: str) -> dict | None:
        return db.row(self.conn, "SELECT * FROM contacts WHERE fpr=?", (fpr,))

    def name_of(self, fpr: str) -> str:
        if fpr == self.fpr:
            return self.profile["name"]
        c = self.contact(fpr)
        return c["name"] if c else fpr[:9]

    def pinned_ed(self, fpr: str) -> bytes | None:
        if fpr == self.fpr:
            return self.identity.ed_pub_bytes()
        c = self.contact(fpr)
        return c["ed_pub"] if c else None

    # --- credentials ------------------------------------------------------

    def _cred(self, cred_id: str) -> dict | None:
        return db.row(self.conn, "SELECT * FROM credentials WHERE id=?", (cred_id,))

    @staticmethod
    def _tier(cred: dict) -> str:
        return "service" if cred["scope"] == "group" else "personal"

    def add_personal_credential(self, meta: dict, secret: str, cred_id: str | None = None,
                                ts: float | None = None) -> str:
        cid = cred_id or db.new_id()
        ts = ts or db.now()
        db.insert(self.conn, "credentials", {
            "id": cid, "scope": "personal", "group_id": None, "owner_fpr": self.fpr, "name": meta["name"],
            "url": meta.get("url", ""), "username": meta.get("username", ""),
            "account_type": meta.get("account_type", "Application"), "criticality": meta.get("criticality", "Medium"),
            "notes": meta.get("notes", ""), "secret_ct": self.vault.enc("personal", "cred", cid, secret.encode()),
            "created_at": ts, "updated_at": ts, "rotated_at": ts})
        self.audit.append("CRED_CREATED", {"cred_id": cid, "cred_name": meta["name"]}, {"scope": "personal"}, ts=ts)
        return cid

    def add_group_secret(self, group_id: str, meta: dict, secret: str, ts: float | None = None) -> None:
        cid = meta["cred_id"]
        ts = ts or db.now()
        db.insert(self.conn, "credentials", {
            "id": cid, "scope": "group", "group_id": group_id, "owner_fpr": None, "name": meta["name"],
            "url": meta.get("url", ""), "username": meta.get("username", ""),
            "account_type": meta.get("account_type", ""), "criticality": meta.get("criticality", "Medium"),
            "notes": meta.get("notes", ""), "secret_ct": self.vault.enc("service", "cred", cid, secret.encode()),
            "created_at": ts, "updated_at": ts, "rotated_at": ts}, replace=True)

    def update_credential(self, cred_id: str, meta: dict, secret: str | None = None) -> None:
        cred = self._cred(cred_id)
        if not cred or cred["scope"] != "personal":
            raise EngineError("only personal credentials can be edited here")
        values = {k: meta[k] for k in ("name", "url", "username", "account_type", "criticality", "notes") if k in meta}
        values["updated_at"] = db.now()
        if secret is not None:
            values["secret_ct"] = self.vault.enc("personal", "cred", cred_id, secret.encode())
            values["rotated_at"] = values["updated_at"]
        db.update(self.conn, "credentials", "id", cred_id, values)
        self.audit.append("CRED_UPDATED", {"cred_id": cred_id, "cred_name": values.get("name", cred["name"])},
                          {"secret_changed": secret is not None})
        if secret is not None:
            self._close_rotation(cred_id, "Secret changed")

    def delete_credential(self, cred_id: str) -> None:
        cred = self._cred(cred_id)
        if not cred or cred["scope"] != "personal":
            raise EngineError("only personal credentials can be deleted")
        self.conn.execute("DELETE FROM credentials WHERE id=?", (cred_id,))
        self.audit.append("CRED_DELETED", {"cred_id": cred_id, "cred_name": cred["name"]})

    def credential_secret(self, cred_id: str) -> str:
        cred = self._cred(cred_id)
        if not cred:
            raise EngineError("unknown credential")
        return self.vault.dec(self._tier(cred), "cred", cred_id, cred["secret_ct"]).decode()

    def reveal_credential(self, cred_id: str, action: str = "CRED_VIEWED") -> str:
        secret = self.credential_secret(cred_id)
        self.audit.append(action, {"cred_id": cred_id, "cred_name": self._cred(cred_id)["name"]})
        return secret

    # --- group helpers ----------------------------------------------------

    def _co_custodians(self, group_id: str | None) -> list[str]:
        if not group_id:
            return []
        head = groups.head_doc(self.conn, group_id)
        if not head or not groups.is_custodian(head, self.fpr):
            return []
        return [c["fpr"] for c in head["custodians"] if c["fpr"] != self.fpr]

    def _sync(self, group_id: str | None, kind: str, row: dict) -> list[Out]:
        to = self._co_custodians(group_id)
        if not to:
            return []
        row = {k: v for k, v in row.items() if k != "secret_ct"}
        return [Out(to, "sync", {"kind": kind, "group_id": group_id, "row": row})]

    def _lease_group_cred(self, head: dict, cred_id: str) -> dict:
        for c in head["credentials"]:
            if c["cred_id"] == cred_id:
                return c
        raise EngineError("credential not in group")

    # --- requests (requester side) -----------------------------------------

    def create_request_out(self, target: dict, ticket: str, reason: str, minutes: int) -> list[Out]:
        ticket, reason = (ticket or "").strip(), (reason or "").strip()
        if not ticket or not reason:
            raise EngineError("a ticket reference and a justification are required")
        minutes = int(minutes)
        if not 1 <= minutes <= MAX_MINUTES:
            raise EngineError(f"duration must be between 1 and {MAX_MINUTES} minutes")
        rid = db.new_id()
        body = {"request_id": rid, "ticket": ticket, "reason": reason, "minutes": minutes,
                "requester_name": self.profile["name"]}
        row = {"id": rid, "direction": "out", "requester_fpr": self.fpr, "requester_name": self.profile["name"],
               "ticket": ticket, "reason": reason, "minutes": minutes, "status": "pending", "created_at": db.now()}
        if target.get("group_id"):
            head = groups.head_doc(self.conn, target["group_id"])
            if not head:
                raise EngineError("unknown group")
            c = self._lease_group_cred(head, target["cred_id"])
            to = [p["fpr"] for p in head["custodians"] if p["fpr"] != self.fpr]
            body.update(group_id=head["group_id"], cred_id=c["cred_id"], cred_name=c["name"])
            row.update(group_id=head["group_id"], cred_id=c["cred_id"], cred_name=c["name"],
                       criticality=c.get("criticality"), target_name=f"{head['name']} custodians")
            outs = [Out(to, "request", body, any=True)]
        else:
            owner = self.contact(target.get("owner_fpr", ""))
            if not owner:
                raise EngineError("you are not paired with that person")
            desc = (target.get("description") or "").strip()
            if not desc:
                raise EngineError("describe which credential you need")
            body.update(description=desc, cred_name=desc)
            row.update(target_fpr=owner["fpr"], target_name=owner["name"], cred_name=desc)
            outs = [Out([owner["fpr"]], "request", body)]
        db.insert(self.conn, "requests", row)
        self.audit.append("REQUEST_SENT", {"request_id": rid, "cred_name": row["cred_name"]},
                          {"ticket": ticket, "minutes": minutes, "to": row["target_name"]})
        return outs

    # --- requests (approver side) -------------------------------------------

    def _receive_request(self, body: dict, sender: str) -> list[Out]:
        rid = str(body["request_id"])
        if db.row(self.conn, "SELECT id FROM requests WHERE id=?", (rid,)):
            return []
        minutes = int(body["minutes"])
        if not 1 <= minutes <= MAX_MINUTES:
            raise EngineError("bad duration")
        row = {"id": rid, "direction": "in", "requester_fpr": sender, "requester_name": self.name_of(sender),
               "target_fpr": self.fpr, "target_name": self.profile["name"], "ticket": str(body.get("ticket", "")),
               "reason": str(body.get("reason", "")), "minutes": minutes, "status": "pending",
               "created_at": db.now()}
        if body.get("group_id"):
            head = groups.head_doc(self.conn, str(body["group_id"]))
            if not head or not groups.is_custodian(head, self.fpr):
                raise EngineError("not a custodian of that group")
            c = self._lease_group_cred(head, str(body["cred_id"]))
            local = self._group_cred(c["cred_id"], head["group_id"])
            row.update(group_id=head["group_id"], cred_id=local["id"], cred_name=local["name"],
                       criticality=local["criticality"])
            decision = decide(groups.is_member(head, sender), head["policy"], minutes, local["criticality"] or "")
        else:
            row.update(cred_name=str(body.get("description", ""))[:200])
            decision = "manual"
        db.insert(self.conn, "requests", row)
        self.audit.append("REQUEST_RECEIVED", {"request_id": rid, "cred_name": row["cred_name"]},
                          {"from": row["requester_name"], "ticket": row["ticket"], "minutes": minutes,
                           "decision": decision})
        if decision == "auto":
            return self._approve(row, minutes, auto=True)
        if decision == "deny":
            return self._deny(row, "Group policy does not allow requests from non-members", auto=True)
        return self._sync(row.get("group_id"), "request", row)

    def _group_cred(self, cred_id: str, group_id: str) -> dict:
        cred = self._cred(cred_id)
        if not cred or cred["scope"] != "group" or cred["group_id"] != group_id:
            raise EngineError("custodian does not hold that credential for this group")
        return cred

    def _pending(self, request_id: str) -> dict:
        req = db.row(self.conn, "SELECT * FROM requests WHERE id=? AND direction IN ('in','sync')", (request_id,))
        if not req:
            raise EngineError("unknown request")
        if req["status"] != "pending":
            raise EngineError(f"request is already {req['status']}")
        return req

    def approve(self, request_id: str, minutes: int | None = None, cred_id: str | None = None) -> list[Out]:
        req = self._pending(request_id)
        minutes = min(int(minutes or req["minutes"]), req["minutes"])
        if minutes < 1:
            raise EngineError("bad duration")
        if not req["group_id"]:
            cred = self._cred(cred_id or "")
            if not cred or cred["scope"] != "personal":
                raise EngineError("choose one of your credentials to share")
            req["cred_id"], req["cred_name"], req["criticality"] = cred["id"], cred["name"], cred["criticality"]
            db.update(self.conn, "requests", "id", request_id,
                      {"cred_id": cred["id"], "cred_name": cred["name"], "criticality": cred["criticality"]})
        return self._approve(req, minutes, auto=False)

    def _approve(self, req: dict, minutes: int, auto: bool) -> list[Out]:
        if req.get("group_id"):
            cred = self._group_cred(req["cred_id"], req["group_id"])
        else:
            cred = self._cred(req["cred_id"])
            if not cred or cred["scope"] != "personal":
                raise EngineError("choose one of your credentials to share")
        secret = self.vault.dec(self._tier(cred), "cred", cred["id"], cred["secret_ct"]).decode()
        now = db.now()
        existing = db.row(self.conn, "SELECT * FROM leases WHERE direction IN ('out','sync') AND holder_fpr=? AND cred_id=? "
                                     "AND status='active' AND expires_at>?", (req["requester_fpr"], cred["id"], now))
        if existing:
            lease = existing
            lease["expires_at"] = max(existing["expires_at"], now + minutes * 60)
            db.update(self.conn, "leases", "id", lease["id"], {"expires_at": lease["expires_at"]})
            event = "LEASE_EXTENDED"
        else:
            lease = {"id": db.new_id(), "direction": "out", "cred_id": cred["id"], "cred_name": cred["name"],
                     "group_id": cred["group_id"], "username": cred["username"], "url": cred["url"],
                     "criticality": cred["criticality"], "holder_fpr": req["requester_fpr"],
                     "holder_name": req["requester_name"], "grantor_fpr": self.fpr,
                     "grantor_name": self.profile["name"], "request_id": req["id"], "ticket": req["ticket"],
                     "granted_at": now, "expires_at": now + minutes * 60, "status": "active"}
            db.insert(self.conn, "leases", lease)
            event = "LEASE_GRANTED"
        status = "auto_approved" if auto else "approved"
        db.update(self.conn, "requests", "id", req["id"],
                  {"status": status, "decided_by": self.profile["name"], "decided_at": now, "lease_id": lease["id"]})
        req.update(status=status, decided_by=self.profile["name"], decided_at=now, lease_id=lease["id"])
        subject = {"request_id": req["id"], "lease_id": lease["id"], "cred_id": cred["id"], "cred_name": cred["name"]}
        self.audit.append("REQUEST_AUTO_APPROVED" if auto else "REQUEST_APPROVED", subject,
                          {"holder": req["requester_name"], "minutes": minutes, "ticket": req["ticket"]})
        self.audit.append(event, subject, {"holder": req["requester_name"], "expires_at": lease["expires_at"]})
        body = {"lease_id": lease["id"], "request_id": req["id"], "cred_id": cred["id"], "cred_name": cred["name"],
                "username": cred["username"], "url": cred["url"], "criticality": cred["criticality"],
                "group_id": cred["group_id"], "secret": secret, "granted_at": lease["granted_at"],
                "expires_at": lease["expires_at"], "ticket": req["ticket"]}
        outs = [Out([req["requester_fpr"]], "lease", body)]
        outs += self._sync(cred["group_id"], "lease", lease) + self._sync(cred["group_id"], "request", req)
        return outs

    def deny(self, request_id: str, comment: str) -> list[Out]:
        return self._deny(self._pending(request_id), (comment or "").strip() or "Denied", auto=False)

    def _deny(self, req: dict, comment: str, auto: bool) -> list[Out]:
        now = db.now()
        db.update(self.conn, "requests", "id", req["id"],
                  {"status": "denied", "decided_by": "policy" if auto else self.profile["name"],
                   "decided_at": now, "comment": comment})
        req.update(status="denied", comment=comment, decided_at=now)
        self.audit.append("REQUEST_DENIED", {"request_id": req["id"], "cred_name": req["cred_name"]},
                          {"holder": req["requester_name"], "comment": comment, "auto": auto})
        return ([Out([req["requester_fpr"]], "denial", {"request_id": req["id"], "comment": comment})]
                + self._sync(req.get("group_id"), "request", req))

    # --- leases (holder side) -----------------------------------------------

    def _my_request(self, request_id: str, sender: str) -> dict:
        req = db.row(self.conn, "SELECT * FROM requests WHERE id=? AND direction='out'", (request_id,))
        if not req:
            raise EngineError("no matching request")
        if req["group_id"]:
            head = groups.head_doc(self.conn, req["group_id"])
            if not head or not groups.is_custodian(head, sender):
                raise EngineError("sender is not a custodian of that group")
        elif req["target_fpr"] != sender:
            raise EngineError("sender is not the owner asked")
        return req

    def _receive_lease(self, body: dict, sender: str) -> list[Out]:
        req = self._my_request(str(body["request_id"]), sender)
        lid = str(body["lease_id"])
        if db.row(self.conn, "SELECT lease_id FROM tombstones WHERE lease_id=?", (lid,)):
            raise EngineError("this checkout was revoked before it arrived")
        secret_ct = self.vault.enc("service", "lease", lid, str(body["secret"]).encode())
        existing = db.row(self.conn, "SELECT * FROM leases WHERE id=? AND direction='in'", (lid,))
        if existing:
            db.update(self.conn, "leases", "id", lid, {"expires_at": float(body["expires_at"]),
                                                      "secret_ct": secret_ct, "status": "active", "ended_at": None})
        else:
            db.insert(self.conn, "leases", {
                "id": lid, "direction": "in", "cred_id": str(body["cred_id"]), "cred_name": str(body["cred_name"]),
                "group_id": body.get("group_id"), "username": body.get("username"), "url": body.get("url"),
                "criticality": body.get("criticality"), "holder_fpr": self.fpr, "holder_name": self.profile["name"],
                "grantor_fpr": sender, "grantor_name": self.name_of(sender), "request_id": req["id"],
                "ticket": body.get("ticket"), "granted_at": float(body.get("granted_at") or db.now()),
                "expires_at": float(body["expires_at"]), "status": "active", "secret_ct": secret_ct})
        db.update(self.conn, "requests", "id", req["id"],
                  {"status": "approved", "decided_by": self.name_of(sender), "decided_at": db.now(), "lease_id": lid,
                   "target_fpr": sender})
        lease = db.row(self.conn, "SELECT * FROM leases WHERE id=?", (lid,))
        self.audit.append("LEASE_RECEIVED", {"lease_id": lid, "cred_id": lease["cred_id"],
                                             "cred_name": lease["cred_name"]},
                          {"from": lease["grantor_name"], "expires_at": lease["expires_at"]})
        return [self._receipt("RECEIVED", lease, [sender])]

    def _receive_denial(self, body: dict, sender: str) -> list[Out]:
        req = self._my_request(str(body["request_id"]), sender)
        db.update(self.conn, "requests", "id", req["id"],
                  {"status": "denied", "comment": str(body.get("comment", ""))[:500],
                   "decided_by": self.name_of(sender), "decided_at": db.now()})
        self.audit.append("REQUEST_DENIED", {"request_id": req["id"], "cred_name": req["cred_name"]},
                          {"by": self.name_of(sender), "comment": body.get("comment", "")})
        return []

    def _lease_in(self, lease_id: str) -> dict:
        lease = db.row(self.conn, "SELECT * FROM leases WHERE id=? AND direction='in'", (lease_id,))
        if not lease:
            raise EngineError("unknown checkout")
        return lease

    def reveal_lease(self, lease_id: str) -> tuple[str, list[Out]]:
        lease = self._lease_in(lease_id)
        if lease["status"] != "active" or lease["expires_at"] <= db.now():
            raise EngineError("this checkout has ended")
        secret = self.vault.dec("service", "lease", lease_id, lease["secret_ct"]).decode()
        self.audit.append("LEASE_VIEWED", {"lease_id": lease_id, "cred_id": lease["cred_id"],
                                           "cred_name": lease["cred_name"]})
        return secret, [self._receipt("VIEWED", lease, [lease["grantor_fpr"]])]

    def _end_in(self, lease: dict, status: str, event: str, notify: list[str]) -> list[Out]:
        now = db.now()
        db.update(self.conn, "leases", "id", lease["id"], {"status": status, "ended_at": now, "secret_ct": None})
        lease = dict(lease, status=status, ended_at=now)
        self.audit.append(event, {"lease_id": lease["id"], "cred_id": lease["cred_id"],
                                  "cred_name": lease["cred_name"]}, {"grantor": lease["grantor_name"]})
        kind = {"checked_in": "CHECKED_IN", "expired": "EXPIRED", "revoked": "REVOKED"}[status]
        return [self._receipt(kind, lease, list(dict.fromkeys(notify)))]

    def checkin(self, lease_id: str) -> list[Out]:
        lease = self._lease_in(lease_id)
        if lease["status"] != "active":
            raise EngineError("this checkout has already ended")
        return self._end_in(lease, "checked_in", "LEASE_CHECKED_IN", [lease["grantor_fpr"]])

    def _receive_revoke(self, body: dict, sender: str) -> list[Out]:
        lid = str(body["lease_id"])
        if not db.row(self.conn, "SELECT id FROM leases WHERE id=? AND direction='in'", (lid,)):
            # the revoke overtook its lease: remember it so the lease is refused when it lands
            self.conn.execute("INSERT OR IGNORE INTO tombstones (lease_id, ts) VALUES (?, ?)", (lid, db.now()))
            return []
        lease = self._lease_in(lid)
        allowed = sender == lease["grantor_fpr"]
        if not allowed and lease["group_id"]:
            head = groups.head_doc(self.conn, lease["group_id"])
            allowed = bool(head and groups.is_custodian(head, sender))
        if not allowed:
            raise EngineError("sender may not revoke this checkout")
        if lease["status"] != "active":
            return []
        return self._end_in(lease, "revoked", "LEASE_REVOKED", [lease["grantor_fpr"], sender])

    # --- receipts -----------------------------------------------------------

    def _receipt(self, kind: str, lease: dict, to: list[str]) -> Out:
        seq, head = self.audit.head()
        record = {"kind": kind, "lease_id": lease["id"], "cred_id": lease["cred_id"],
                  "cred_name": lease["cred_name"], "holder_fpr": lease["holder_fpr"],
                  "grantor_fpr": lease["grantor_fpr"], "from_fpr": self.fpr, "ts": db.now(),
                  "log_seq": seq, "log_head": head}
        sig = self.identity.sign(crypto.canonical_json(record))
        return Out(to, "receipt", {"record": record, "sig": _b(sig)})

    def _receive_receipt(self, body: dict, sender: str) -> list[Out]:
        record = body["record"]
        if record.get("from_fpr") != sender:
            raise EngineError("receipt identity mismatch")
        if not crypto.verify(self.contact(sender)["ed_pub"], base64.b64decode(body["sig"]),
                             crypto.canonical_json(record)):
            raise EngineError("receipt signature invalid")
        lease = db.row(self.conn, "SELECT * FROM leases WHERE id=? AND direction IN ('out','sync')",
                       (str(record["lease_id"]),))
        if not lease or lease["holder_fpr"] != sender:
            raise EngineError("receipt for unknown checkout")
        db.insert(self.conn, "receipts", {"id": db.new_id(), "peer_fpr": sender, "record": json.dumps(record),
                                          "sig": base64.b64decode(body["sig"]), "received_at": db.now()})
        self.audit.append("RECEIPT_RECEIVED", {"lease_id": lease["id"], "cred_id": lease["cred_id"],
                                               "cred_name": lease["cred_name"]},
                          {"kind": record["kind"], "from": self.name_of(sender)})
        status = {"CHECKED_IN": "checked_in", "EXPIRED": "expired", "REVOKED": "revoked"}.get(record["kind"])
        if status and lease["status"] == "active":
            return self._end_out(lease, status)
        return []

    def _end_out(self, lease: dict, status: str) -> list[Out]:
        now = db.now()
        db.update(self.conn, "leases", "id", lease["id"], {"status": status, "ended_at": now})
        lease = dict(lease, status=status, ended_at=now)
        if lease["direction"] == "out":
            event = {"checked_in": "LEASE_CHECKED_IN", "expired": "LEASE_EXPIRED", "revoked": "LEASE_REVOKED"}[status]
            self.audit.append(event, {"lease_id": lease["id"], "cred_id": lease["cred_id"],
                                      "cred_name": lease["cred_name"]}, {"holder": lease["holder_name"]})
        outs = self._sync(lease["group_id"], "lease", lease)
        verb = {"checked_in": "checked it in", "expired": "checkout expired", "revoked": "checkout revoked"}[status]
        return outs + self.raise_rotation(lease["cred_id"], f"{lease['holder_name']} held this credential ({verb})")

    def revoke(self, lease_id: str) -> list[Out]:
        lease = db.row(self.conn, "SELECT * FROM leases WHERE id=? AND direction IN ('out','sync')", (lease_id,))
        if not lease:
            raise EngineError("unknown checkout")
        if lease["status"] != "active":
            raise EngineError("this checkout has already ended")
        self.audit.append("LEASE_REVOKED", {"lease_id": lease_id, "cred_id": lease["cred_id"],
                                            "cred_name": lease["cred_name"]}, {"holder": lease["holder_name"]})
        return [Out([lease["holder_fpr"]], "revoke", {"lease_id": lease_id})] + self._end_out(lease, "revoked")

    # --- rotation -----------------------------------------------------------

    def raise_rotation(self, cred_id: str, reason: str, ts: float | None = None) -> list[Out]:
        cred = self._cred(cred_id)
        if not cred or db.row(self.conn, "SELECT id FROM rotation_tasks WHERE cred_id=? AND status='open'", (cred_id,)):
            return []
        task = {"id": db.new_id(), "cred_id": cred_id, "cred_name": cred["name"], "reason": reason,
                "status": "open", "created_at": ts or db.now()}
        db.insert(self.conn, "rotation_tasks", task)
        self.audit.append("ROTATION_DUE", {"cred_id": cred_id, "cred_name": cred["name"]}, {"reason": reason}, ts=ts)
        return self._sync(cred["group_id"], "rotation", task)

    def _close_rotation(self, cred_id: str, note: str, status: str = "done", by: str | None = None) -> None:
        self.conn.execute("UPDATE rotation_tasks SET status=?, closed_at=?, closed_by=?, note=? "
                          "WHERE cred_id=? AND status='open'", (status, db.now(), by or self.profile["name"], note, cred_id))

    def rotate(self, cred_id: str, new_secret: str) -> list[Out]:
        cred = self._cred(cred_id)
        if not cred:
            raise EngineError("unknown credential")
        if not new_secret:
            raise EngineError("new secret required")
        now = db.now()
        db.update(self.conn, "credentials", "id", cred_id, {
            "secret_ct": self.vault.enc(self._tier(cred), "cred", cred_id, new_secret.encode()),
            "updated_at": now, "rotated_at": now})
        self._close_rotation(cred_id, "Rotated")
        self.audit.append("ROTATION_DONE", {"cred_id": cred_id, "cred_name": cred["name"]})
        to = self._co_custodians(cred["group_id"])
        if not to:
            return []
        return [Out(to, "sync", {"kind": "secret", "group_id": cred["group_id"],
                                 "row": {"cred_id": cred_id, "secret": new_secret, "rotated_at": now,
                                         "by": self.profile["name"]}})]

    def dismiss_rotation(self, task_id: str, note: str) -> list[Out]:
        task = db.row(self.conn, "SELECT * FROM rotation_tasks WHERE id=?", (task_id,))
        if not task or task["status"] != "open":
            raise EngineError("no open rotation task")
        if not (note or "").strip():
            raise EngineError("a reason is required to dismiss")
        self.conn.execute("UPDATE rotation_tasks SET status='dismissed', closed_at=?, closed_by=?, note=? WHERE id=?",
                          (db.now(), self.profile["name"], note, task_id))
        self.audit.append("ROTATION_DISMISSED", {"cred_id": task["cred_id"], "cred_name": task["cred_name"]},
                          {"note": note})
        task = db.row(self.conn, "SELECT * FROM rotation_tasks WHERE id=?", (task_id,))
        cred = self._cred(task["cred_id"])
        return self._sync(cred["group_id"] if cred else None, "rotation", task)

    # --- custodian sync -----------------------------------------------------

    SYNC_COLUMNS = {
        "lease": ("id", "cred_id", "holder_fpr", "grantor_fpr", "request_id", "ticket", "granted_at", "expires_at",
                  "status", "ended_at"),
        "request": ("id", "requester_fpr", "cred_id", "ticket", "reason", "minutes", "status", "decided_by",
                    "decided_at", "comment", "created_at", "lease_id"),
        "rotation": ("id", "cred_id", "reason", "status", "created_at", "closed_at", "closed_by", "note"),
    }
    SYNC_IGNORED = {"group_id", "direction", "secret_ct", "cred_name", "criticality", "username", "url",
                    "holder_name", "grantor_name", "requester_name", "target_fpr", "target_name", "cred_name"}
    SYNC_STATES = {"lease": ("active",) + TERMINAL,
                   "request": ("pending", "approved", "auto_approved", "denied", "expired"),
                   "rotation": ("open", "done", "dismissed")}

    def _clean_sync_row(self, kind: str, row: dict, head: dict) -> dict:
        cols = self.SYNC_COLUMNS[kind]
        if set(row) - set(cols) - self.SYNC_IGNORED:
            raise EngineError("unexpected fields in sync")
        if row.get("group_id") not in (None, head["group_id"]):
            raise EngineError("sync row belongs to another group")
        clean = {c: row.get(c) for c in cols}
        for c, v in clean.items():
            if v is not None and (isinstance(v, bool) or not isinstance(v, (str, int, float))):
                raise EngineError(f"bad value for {c}")
            if isinstance(v, str) and len(v) > 2000:
                raise EngineError(f"value too long for {c}")
        if clean["status"] not in self.SYNC_STATES[kind]:
            raise EngineError(f"bad {kind} state")
        meta = self._lease_group_cred(head, str(clean["cred_id"]))
        clean["group_id"] = head["group_id"]
        if kind != "rotation":
            clean.update(cred_name=meta["name"], criticality=meta.get("criticality"))
        else:
            clean["cred_name"] = meta["name"]
        return clean

    def _known(self, fpr) -> bool:
        return fpr == self.fpr or bool(self.contact(str(fpr)))

    def _receive_sync(self, body: dict, sender: str) -> list[Out]:
        gid = str(body.get("group_id"))
        if sender not in self._co_custodians(gid):
            raise EngineError("sync from a non-custodian")
        head = groups.head_doc(self.conn, gid)
        kind, row = body["kind"], dict(body["row"])
        if kind == "lease":
            row = self._clean_sync_row(kind, row, head)
            if row["grantor_fpr"] not in {c["fpr"] for c in head["custodians"]} or not self._known(row["holder_fpr"]):
                raise EngineError("bad checkout sync")
            row.update(holder_name=self.name_of(row["holder_fpr"]), grantor_name=self.name_of(row["grantor_fpr"]))
            mine = db.row(self.conn, "SELECT * FROM leases WHERE id=?", (row["id"],))
            if not mine:
                db.insert(self.conn, "leases", dict(row, direction="sync", secret_ct=None))
            elif mine["direction"] == "in" or mine["group_id"] != gid:
                raise EngineError("sync may not touch that checkout")
            elif mine["status"] == "active":
                values = {"expires_at": max(mine["expires_at"] or 0, float(row["expires_at"] or 0))}
                if row["status"] in TERMINAL:
                    values.update(status=row["status"], ended_at=row["ended_at"])
                db.update(self.conn, "leases", "id", row["id"], values)
        elif kind == "request":
            row = self._clean_sync_row(kind, row, head)
            if not self._known(row["requester_fpr"]):
                raise EngineError("requester is not a known peer")
            row["requester_name"] = self.name_of(row["requester_fpr"])
            mine = db.row(self.conn, "SELECT * FROM requests WHERE id=?", (row["id"],))
            if not mine:
                db.insert(self.conn, "requests", dict(row, direction="sync"))
            elif mine["direction"] == "out" or mine["group_id"] != gid:
                raise EngineError("sync may not touch that request")
            elif mine["status"] == "pending" and row["status"] != "pending":
                db.update(self.conn, "requests", "id", row["id"],
                          {k: row[k] for k in ("status", "decided_by", "decided_at", "comment", "lease_id")})
        elif kind == "rotation":
            row = self._clean_sync_row(kind, row, head)
            self._group_cred(row["cred_id"], gid)
            row.pop("group_id")
            mine = db.row(self.conn, "SELECT * FROM rotation_tasks WHERE id=?", (row["id"],))
            if mine:
                if row["status"] != "open":
                    db.update(self.conn, "rotation_tasks", "id", row["id"],
                              {k: row[k] for k in ("status", "closed_at", "closed_by", "note")})
            elif row["status"] != "open":
                self._close_rotation(row["cred_id"], row["note"] or "", row["status"], row["closed_by"])
            elif not db.row(self.conn, "SELECT id FROM rotation_tasks WHERE cred_id=? AND status='open'",
                            (row["cred_id"],)):
                db.insert(self.conn, "rotation_tasks", row)
        elif kind == "secret":
            cred = self._cred(str(row["cred_id"]))
            if not cred:
                meta = next((c for c in head["credentials"] if c["cred_id"] == row["cred_id"]), None)
                if not meta:
                    raise EngineError("unknown group credential")
                self.add_group_secret(gid, meta, str(row["secret"]))
                cred = self._cred(meta["cred_id"])
            if cred["scope"] != "group" or cred["group_id"] != gid:
                raise EngineError("unknown group credential")
            db.update(self.conn, "credentials", "id", cred["id"], {
                "secret_ct": self.vault.enc("service", "cred", cred["id"], str(row["secret"]).encode()),
                "updated_at": db.now(), "rotated_at": db.now()})
            by = self.name_of(sender)
            self._close_rotation(cred["id"], f"Rotated by {by}", by=by)
            self.audit.append("ROTATION_SYNCED", {"cred_id": cred["id"], "cred_name": cred["name"]}, {"from": by})
        else:
            raise EngineError("unknown sync kind")
        return []

    # --- groups -------------------------------------------------------------

    def _receive_group_docs(self, body: dict, sender: str) -> list[Out]:
        docs = sorted(body.get("docs", []), key=lambda d: d["version"])
        if not docs or any(d.get("group_id") != body.get("group_id") for d in docs):
            raise EngineError("bad group chain")
        head = groups.head_doc(self.conn, docs[0]["group_id"])
        fresh = head is None
        accepted = []
        for doc in docs:
            try:
                # A node new to the group is often absent from v1; only the final version must list it.
                result = groups.validate_extension(head, doc, None if fresh else self.fpr, self.pinned_ed)
            except groups.GroupError as e:
                if e.code == "FORK":
                    db.add_alert(self.conn, "GROUP_FORK",
                                 f"Conflicting version of group '{doc.get('name')}' from {self.name_of(sender)}: {e}",
                                 doc["group_id"])
                self.audit.append("GROUP_REJECTED", {"group_id": doc["group_id"]},
                                  {"from": self.name_of(sender), "error": e.code, "version": doc["version"]})
                return []
            if result == "accept":
                accepted.append(doc)
                head = doc
        if fresh and accepted and not groups.is_member(accepted[-1], self.fpr):
            return []
        for doc in accepted:
            groups.store(self.conn, doc)
            self.audit.append("GROUP_SYNCED", {"group_id": doc["group_id"], "group_name": doc["name"]},
                              {"version": doc["version"], "from": self.name_of(sender)})
        return []

    def _push_group(self, group_id: str, extra: list[str] = ()) -> list[Out]:
        head = groups.head_doc(self.conn, group_id)
        to = [p["fpr"] for p in head["members"] + head["custodians"] if p["fpr"] != self.fpr]
        to += [f for f in extra if f not in to and f != self.fpr]
        return [Out(to, "group_docs", {"group_id": group_id, "docs": groups.chain(self.conn, group_id)})]

    def create_group(self, name: str, description: str, policy: dict, custodian_fprs: list[str],
                     member_fprs: list[str], ts: float | None = None) -> tuple[str, list[Out]]:
        gid = db.new_id()
        me = groups.person(self.profile["name"], self.identity, self.profile.get("title", ""))
        cust = [me] + [groups.person_from_contact(self._need_contact(f)) for f in custodian_fprs if f != self.fpr]
        mem = [groups.person_from_contact(self._need_contact(f)) for f in member_fprs
               if f != self.fpr and f not in custodian_fprs]
        doc = groups.make_genesis(gid, name, description, cust, mem, policy, [], [self.identity])
        groups.store(self.conn, doc)
        self.audit.append("GROUP_CREATED", {"group_id": gid, "group_name": name}, {"version": 1}, ts=ts)
        return gid, self._push_group(gid)

    def _need_contact(self, fpr: str) -> dict:
        c = self.contact(fpr)
        if not c:
            raise EngineError("not paired with that person")
        return c

    def update_group(self, group_id: str, changes: dict) -> list[Out]:
        head = groups.head_doc(self.conn, group_id)
        if not head or not groups.is_custodian(head, self.fpr):
            raise EngineError("only custodians can change a group")
        new = {}
        outs: list[Out] = []
        removed: list[str] = []
        members = list(head["members"])
        if changes.get("members_add"):
            known = {p["fpr"] for p in members + head["custodians"]}
            members += [groups.person_from_contact(self._need_contact(f)) for f in changes["members_add"]
                        if f not in known]
        if changes.get("members_remove"):
            removed = list(changes["members_remove"])
            members = [m for m in members if m["fpr"] not in removed]
        if members != head["members"]:
            new["members"] = members
        if "policy" in changes:
            new["policy"] = dict(head["policy"], **changes["policy"])
        if "description" in changes:
            new["description"] = str(changes["description"])
        creds = list(head["credentials"])
        for c in changes.get("credentials_add", []):
            meta = {k: c.get(k, "") for k in ("name", "url", "username", "account_type", "criticality")}
            meta["cred_id"] = c.get("cred_id") or db.new_id()
            self.add_group_secret(group_id, meta, c["secret"])
            creds.append(meta)
            outs += [Out(self._co_custodians(group_id), "sync", {"kind": "secret", "group_id": group_id,
                         "row": {"cred_id": meta["cred_id"], "secret": c["secret"], "rotated_at": db.now(),
                                 "by": self.profile["name"]}})] if self._co_custodians(group_id) else []
        if changes.get("credentials_remove"):
            creds = [c for c in creds if c["cred_id"] not in changes["credentials_remove"]]
        if creds != head["credentials"]:
            new["credentials"] = creds
        if not new:
            raise EngineError("nothing changed")
        doc = groups.make_next(head, new, [self.identity])
        groups.store(self.conn, doc)
        self.audit.append("GROUP_UPDATED", {"group_id": group_id, "group_name": doc["name"]},
                          {"version": doc["version"], "changes": sorted(new)})
        outs = self._push_group(group_id, removed) + outs
        cutoff = db.now() - ROTATION_WINDOW_DAYS * DAY
        for fpr in removed:
            for lease in db.rows(self.conn, "SELECT DISTINCT cred_id FROM leases WHERE holder_fpr=? AND group_id=? "
                                            "AND granted_at>?", (fpr, group_id, cutoff)):
                outs += self.raise_rotation(lease["cred_id"], f"{self.name_of(fpr)} was removed from the group")
        return outs

    # --- sweeper ------------------------------------------------------------

    def sweep(self, now: float | None = None) -> list[Out]:
        now = now or db.now()
        outs: list[Out] = []
        for lease in db.rows(self.conn, "SELECT * FROM leases WHERE status='active' AND expires_at<=?", (now,)):
            if lease["direction"] == "in":
                outs += self._end_in(lease, "expired", "LEASE_EXPIRED", [lease["grantor_fpr"]])
            elif lease["direction"] == "out":
                outs += self._end_out(lease, "expired")
            else:
                db.update(self.conn, "leases", "id", lease["id"], {"status": "expired", "ended_at": now})
        for req in db.rows(self.conn, "SELECT * FROM requests WHERE status='pending' AND created_at<?", (now - DAY,)):
            db.update(self.conn, "requests", "id", req["id"], {"status": "expired", "decided_at": now})
            if req["direction"] != "sync":
                self.audit.append("REQUEST_EXPIRED", {"request_id": req["id"], "cred_name": req["cred_name"]})
        return outs

    # --- inbound dispatch ---------------------------------------------------

    def handle(self, msg_type: str, body: dict, sender_fpr: str) -> list[Out]:
        if not self.contact(sender_fpr):
            raise EngineError("message from an unpaired peer")
        for k in IDENTITY_FIELDS:
            if k in body and body[k] != sender_fpr:
                raise EngineError("identity mismatch between channel and message")
        handler = {"request": self._receive_request, "lease": self._receive_lease,
                   "denial": self._receive_denial, "revoke": self._receive_revoke,
                   "receipt": self._receive_receipt, "sync": self._receive_sync,
                   "group_docs": self._receive_group_docs}.get(msg_type)
        if not handler:
            raise EngineError(f"unknown message type {msg_type}")
        try:
            return handler(body, sender_fpr)
        except (KeyError, TypeError, ValueError) as e:
            raise EngineError(f"malformed {msg_type}: {e}") from None
