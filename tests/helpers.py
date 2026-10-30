"""Build in-memory engines and route their outbound messages directly (no network)."""
from p2psec import db as dbmod, groups
from p2psec.audit import AuditLog
from p2psec.crypto import Identity
from p2psec.engine import Engine
from p2psec.vault import Vault

FAST = {"t": 1, "m": 8192, "p": 1}
POLICY = {"auto_approve_members": True, "max_lease_minutes": 240, "default_lease_minutes": 60,
          "allow_non_member_requests": True}


def make_engine(tmp_path, name):
    ident = Identity.generate()
    conn = dbmod.open_db(str(tmp_path / f"{name}.db"))
    vault, _ = Vault.create("pw", params=FAST)
    return Engine(conn, vault, AuditLog(conn, ident), ident, {"name": name, "title": "", "dept": ""})


def pair_all(engines):
    for a in engines:
        for b in engines:
            if a is not b:
                a.add_contact({"fpr": b.fpr, "name": b.profile["name"], "title": "", "dept": "",
                               "ed_pub": b.identity.ed_pub_bytes(), "x_pub": b.identity.x_pub_bytes()})


def setup_group(custodians, members, creds, policy=POLICY, group_id="g1"):
    doc = groups.make_genesis(
        group_id, "Infrastructure", "",
        [groups.person(e.profile["name"], e.identity) for e in custodians],
        [groups.person(e.profile["name"], e.identity) for e in members], policy,
        [{k: c[k] for k in ("cred_id", "name", "url", "username", "account_type", "criticality")} for c in creds],
        [custodians[0].identity])
    for e in custodians + members:
        groups.store(e.conn, doc)
    for e in custodians:
        for c in creds:
            e.add_group_secret(group_id, c, c["secret"])
    return doc


def route(outs, sender, engines, drop=()):
    by_fpr = {e.fpr: e for e in engines}
    queue = [(sender, o) for o in outs]
    while queue:
        src, out = queue.pop(0)
        targets = [f for f in out.to if f in by_fpr and f not in drop]
        if out.any:
            targets = targets[:1]
        for f in targets:
            queue.extend((by_fpr[f], o) for o in by_fpr[f].handle(out.type, out.body, src.fpr))


def cred(cid="c1", criticality="High", secret="S3cr3t!"):
    return {"cred_id": cid, "name": f"cred {cid}", "url": "https://x", "username": "admin",
            "account_type": "Root", "criticality": criticality, "secret": secret}
