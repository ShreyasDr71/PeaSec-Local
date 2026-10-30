"""DEMO ONLY. The fictional P2PSec IT team.

Every container builds *its own* state from this one definition. Keys come from
DEMO_SEED + node id, so all nodes agree on each other's public keys without talking,
and anyone who knows the seed can recompute every private key. Never use outside a demo.
"""
from __future__ import annotations

import string

from . import crypto, db, groups
from .crypto import Identity

HOUR, DAY = 3600, 86400

TEAM = {
    "priya":  {"name": "Priya Nair", "title": "IT Operations Lead", "dept": "IT Operations"},
    "marcus": {"name": "Marcus Chen", "title": "Database Administrator", "dept": "Data Platform"},
    "elena":  {"name": "Elena Rossi", "title": "Security Engineer", "dept": "Information Security"},
    "jamal":  {"name": "Jamal Okafor", "title": "Backend Developer", "dept": "Engineering"},
    "sofia":  {"name": "Sofia Alvarez", "title": "Finance Systems Analyst", "dept": "Finance"},
    "tom":    {"name": "Tom Becker", "title": "Engineering Intern", "dept": "Engineering"},
}

STD = {"auto_approve_members": True, "allow_non_member_requests": True}
GROUPS = [
    {"id": "grp-infra", "name": "Infrastructure", "custodians": ["priya", "elena"], "members": ["marcus", "jamal"],
     "description": "Core infrastructure, virtualization, network and cloud break-glass accounts.",
     "policy": dict(STD, max_lease_minutes=240, default_lease_minutes=60),
     "credentials": [
         ("cred-aws-root", "AWS root account", "https://console.aws.amazon.com", "aws-root@p2psec.example",
          "Cloud Root", "Critical"),
         ("cred-ad-da", "AD Domain Admin", "ldaps://dc01.corp.p2psec.example", "P2PSEC\\da-admin",
          "Domain Admin", "Critical"),
         ("cred-vcenter", "vCenter administrator", "https://vcenter.corp.p2psec.example",
          "administrator@vsphere.local", "Local Admin", "High"),
         ("cred-coresw", "Core switch SSH", "ssh://core-sw01.corp.p2psec.example", "netadmin", "Network Device", "High"),
         ("cred-backup", "Backup server", "https://backup01.corp.p2psec.example", "veeam-svc", "Service Account",
          "Medium"),
     ]},
    {"id": "grp-db", "name": "Databases", "custodians": ["marcus"], "members": ["jamal"],
     "description": "Production and staging database superusers.",
     "policy": dict(STD, max_lease_minutes=120, default_lease_minutes=30),
     "credentials": [
         ("cred-pg-prod", "Prod PostgreSQL", "postgres://pg-prod01.corp.p2psec.example:5432", "pg_admin",
          "Database", "High"),
         ("cred-mysql-stg", "Staging MySQL", "mysql://mysql-stg01.corp.p2psec.example:3306", "root",
          "Database", "Medium"),
         ("cred-redis", "Redis cluster", "redis://redis01.corp.p2psec.example:6379", "default", "Database", "Low"),
     ]},
    {"id": "grp-sec", "name": "Security Tools", "custodians": ["elena"], "members": ["priya"],
     "description": "Security tooling consoles. Members only.",
     "policy": {"auto_approve_members": True, "allow_non_member_requests": False,
                "max_lease_minutes": 60, "default_lease_minutes": 15},
     "credentials": [
         ("cred-siem", "SIEM admin", "https://siem.corp.p2psec.example", "siem-admin", "Application", "High"),
         ("cred-fw", "Firewall management", "https://fw-mgmt.corp.p2psec.example", "fwadmin", "Network Device",
          "Critical"),
         ("cred-edr", "EDR console", "https://edr.corp.p2psec.example", "edr-admin", "Application", "High"),
     ]},
    {"id": "grp-fin", "name": "Finance Apps", "custodians": ["sofia"], "members": [],
     "description": "Finance application administrator accounts.",
     "policy": dict(STD, max_lease_minutes=60, default_lease_minutes=30),
     "credentials": [
         ("cred-payroll", "Payroll portal admin", "https://payroll.p2psec.example", "payroll-admin", "Application",
          "High"),
         ("cred-acct", "Accounting software admin", "https://accounting.p2psec.example", "acct-admin", "Application",
          "High"),
         ("cred-bank", "Corporate bank portal (view-only)", "https://bank.example/corporate", "bank-viewer",
          "Application", "Critical"),
     ]},
]

PERSONAL = {
    "priya": [("Grafana personal", "https://grafana.corp.p2psec.example", "priya.nair", "Application", "Low"),
              ("iDRAC lab hosts", "https://idrac-lab.corp.p2psec.example", "root", "Local Admin", "Medium"),
              ("PagerDuty", "https://p2psec.pagerduty.com", "priya.nair@p2psec.example", "Application", "Low")],
    "marcus": [("pgAdmin workstation", "http://localhost:5050", "marcus", "Application", "Low"),
               ("DB backup S3 key", "s3://p2psec-db-backups", "AKIA-BACKUP-RO", "Service Account", "High")],
    "elena": [("Vulnerability scanner", "https://scanner.corp.p2psec.example", "elena.rossi", "Application", "Medium"),
              ("Pentest jump box", "ssh://jump01.lab.p2psec.example", "elena", "Local Admin", "High"),
              ("Threat intel feed API", "https://intel.example/api", "p2psec-sec", "Application", "Low")],
    "jamal": [("GitHub deploy token", "https://github.com/p2psec", "deploy-bot", "Service Account", "High"),
              ("Staging app admin", "https://staging.p2psec.example/admin", "jamal", "Application", "Low")],
    "sofia": [("Expense tool", "https://expenses.p2psec.example", "sofia.alvarez", "Application", "Medium"),
              ("Tax filing portal", "https://tax.example", "p2psec-finance", "Application", "High")],
    "tom": [("Intern sandbox VM", "ssh://sandbox-tom.lab.p2psec.example", "tom", "Local Admin", "Low")],
}

EXTRA_PAIRS = [("jamal", "sofia")]
ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*-_=+"


def identity(seed: str, node_id: str) -> Identity:
    return Identity.from_seed(seed, node_id)


def secret_for(seed: str, cred_id: str) -> str:
    raw = crypto.hkdf(seed.encode(), b"p2psec-demo-secret", cred_id.encode(), 40)
    return "".join(ALPHABET[b % len(ALPHABET)] for b in raw[:20])


def required_pairs() -> set[frozenset]:
    pairs = {frozenset(p) for p in EXTRA_PAIRS}
    for g in GROUPS:
        for c in g["custodians"]:
            for other in g["custodians"] + g["members"]:
                if other != c:
                    pairs.add(frozenset((c, other)))
    return pairs


def group_doc(seed: str, g: dict) -> dict:
    ids = {n: identity(seed, n) for n in TEAM}
    person = lambda n: groups.person(TEAM[n]["name"], ids[n], TEAM[n]["title"])
    creds = [{"cred_id": c[0], "name": c[1], "url": c[2], "username": c[3], "account_type": c[4],
              "criticality": c[5]} for c in g["credentials"]]
    return groups.make_genesis(g["id"], g["name"], g["description"], [person(n) for n in g["custodians"]],
                               [person(n) for n in g["members"]], g["policy"], creds, [ids[g["custodians"][0]]])


def build(node, params: dict | None = None, addr_of=None) -> None:
    """addr_of(node_id) -> "host:port" where that teammate's node listens."""
    addr_of = addr_of or (lambda n: f"{n}:7600")
    me = node.settings.node_id
    if me not in TEAM:
        raise SystemExit(f"NODE_ID '{me}' is not part of the demo team: {', '.join(TEAM)}")
    seed = node.settings.demo_seed
    now = db.now()
    t0 = now - 14 * DAY
    from .node import DEMO_PASSWORD
    node.setup(DEMO_PASSWORD, TEAM[me], identity(seed, me), params=params, ts=t0, login=me)
    eng, conn = node.engine, node.conn
    events: list[tuple] = []          # (ts, event_type, subject, details)

    def ev(ts, kind, subject, details=None):
        events.append((ts, kind, subject, details or {}))

    fprs = {n: identity(seed, n).fingerprint() for n in TEAM}

    # pairings
    for i, pair in enumerate(sorted(required_pairs(), key=sorted)):
        if me not in pair:
            continue
        (other,) = pair - {me}
        oi = identity(seed, other)
        ts = t0 + HOUR + i * 600
        eng.add_contact({"fpr": oi.fingerprint(), "name": TEAM[other]["name"], "title": TEAM[other]["title"],
                         "dept": TEAM[other]["dept"], "ed_pub": oi.ed_pub_bytes(), "x_pub": oi.x_pub_bytes(),
                         "addr": addr_of(other), "paired_at": ts, "demo": True})
        ev(ts, "PAIRED", {"peer_fpr": oi.fingerprint(), "peer_name": TEAM[other]["name"]}, {"demo_peer": True})

    # groups and custodian secrets
    for g in GROUPS:
        if me not in g["custodians"] + g["members"]:
            continue
        doc = group_doc(seed, g)
        groups.store(conn, doc)
        ts = t0 + 3 * HOUR
        if g["custodians"][0] == me:
            ev(ts, "GROUP_CREATED", {"group_id": g["id"], "group_name": g["name"]}, {"version": 1})
        else:
            ev(ts + 60, "GROUP_SYNCED", {"group_id": g["id"], "group_name": g["name"]}, {"version": 1})
        if me in g["custodians"]:
            for c in doc["credentials"]:
                eng.add_group_secret(g["id"], c, secret_for(seed, c["cred_id"]), ts=ts)
                ev(ts + 5, "CRED_CREATED", {"cred_id": c["cred_id"], "cred_name": c["name"]},
                   {"scope": "group", "group": g["name"]})

    # personal credentials
    for i, (name, url, user, atype, crit) in enumerate(PERSONAL.get(me, [])):
        cid = f"cred-{me}-{i}"
        conn_ts = t0 + 4 * HOUR + i * 300
        db.insert(conn, "credentials", {
            "id": cid, "scope": "personal", "group_id": None, "owner_fpr": fprs[me], "name": name, "url": url,
            "username": user, "account_type": atype, "criticality": crit, "notes": "",
            "secret_ct": node.vault.enc("personal", "cred", cid, secret_for(seed, cid).encode()),
            "created_at": conn_ts, "updated_at": conn_ts, "rotated_at": conn_ts})
        ev(conn_ts, "CRED_CREATED", {"cred_id": cid, "cred_name": name}, {"scope": "personal"})
        ev(now - (i + 2) * DAY + 3 * HOUR, "CRED_VIEWED", {"cred_id": cid, "cred_name": name})

    # routine unlock / lock activity
    for d in range(1, 12):
        ev(now - d * DAY - 6 * HOUR, "UNLOCKED", {"node": me})
        ev(now - d * DAY + 2 * HOUR, "LOCKED", {"node": me}, {"mode": "soft"})

    _history(node, seed, me, fprs, now, ev)

    for ts, kind, subject, details in sorted(events, key=lambda e: e[0]):
        node.audit.append(kind, subject, details, ts=round(ts, 3))


def _history(node, seed, me, fprs, now, ev) -> None:
    conn, vault = node.conn, node.vault
    name = lambda n: TEAM[n]["name"]

    def request(rid, direction, requester, target, group, cred, ticket, reason, minutes, status, created,
                decided=None, decided_by=None, comment=None, lease_id=None, target_name=None):
        db.insert(conn, "requests", {
            "id": rid, "direction": direction, "requester_fpr": fprs[requester], "requester_name": name(requester),
            "target_fpr": fprs[target] if target else None, "target_name": target_name or (name(target) if target else ""),
            "group_id": group, "cred_id": cred[0] if cred else None, "cred_name": cred[1], "criticality": cred[2],
            "ticket": ticket, "reason": reason, "minutes": minutes, "status": status, "decided_by": decided_by,
            "comment": comment, "created_at": created, "decided_at": decided, "lease_id": lease_id})

    def lease(lid, direction, cred, group, holder, grantor, rid, ticket, granted, expires, status, ended=None,
              secret=None, username="", url=""):
        db.insert(conn, "leases", {
            "id": lid, "direction": direction, "cred_id": cred[0], "cred_name": cred[1], "group_id": group,
            "username": username, "url": url, "criticality": cred[2], "holder_fpr": fprs[holder],
            "holder_name": name(holder), "grantor_fpr": fprs[grantor], "grantor_name": name(grantor),
            "request_id": rid, "ticket": ticket, "granted_at": granted, "expires_at": expires, "status": status,
            "ended_at": ended,
            "secret_ct": vault.enc("service", "lease", lid, secret.encode()) if secret else None})

    sub = lambda c, **kw: dict({"cred_id": c[0], "cred_name": c[1]}, **kw)

    # 1. Jamal holds an active, auto-approved checkout of Prod PostgreSQL from Marcus (~45 min left)
    pg = ("cred-pg-prod", "Prod PostgreSQL", "High")
    g1, e1 = now - 15 * 60, now + 45 * 60
    if me == "jamal":
        request("seed-req-pg", "out", "jamal", "marcus", "grp-db", pg, "INC0010442", "Hotfix data migration", 60,
                "approved", g1 - 2, g1, name("marcus"), lease_id="seed-lease-pg", target_name="Databases custodians")
        lease("seed-lease-pg", "in", pg, "grp-db", "jamal", "marcus", "seed-req-pg", "INC0010442", g1, e1, "active",
              secret=secret_for(seed, pg[0]), username="pg_admin", url="postgres://pg-prod01.corp.p2psec.example:5432")
        ev(g1 - 2, "REQUEST_SENT", {"request_id": "seed-req-pg", "cred_name": pg[1]}, {"ticket": "INC0010442"})
        ev(g1, "LEASE_RECEIVED", sub(pg, lease_id="seed-lease-pg"), {"from": name("marcus")})
        ev(g1 + 90, "LEASE_VIEWED", sub(pg, lease_id="seed-lease-pg"))
    if me == "marcus":
        request("seed-req-pg", "in", "jamal", "marcus", "grp-db", pg, "INC0010442", "Hotfix data migration", 60,
                "auto_approved", g1 - 2, g1, name("marcus"), lease_id="seed-lease-pg")
        lease("seed-lease-pg", "out", pg, "grp-db", "jamal", "marcus", "seed-req-pg", "INC0010442", g1, e1, "active",
              username="pg_admin", url="postgres://pg-prod01.corp.p2psec.example:5432")
        ev(g1 - 1, "REQUEST_RECEIVED", {"request_id": "seed-req-pg", "cred_name": pg[1]},
           {"from": name("jamal"), "decision": "auto"})
        ev(g1, "REQUEST_AUTO_APPROVED", sub(pg, request_id="seed-req-pg"), {"holder": name("jamal"), "minutes": 60})
        ev(g1, "LEASE_GRANTED", sub(pg, lease_id="seed-lease-pg"), {"holder": name("jamal")})
        ev(g1 + 1, "RECEIPT_RECEIVED", sub(pg, lease_id="seed-lease-pg"), {"kind": "RECEIVED", "from": name("jamal")})
        ev(g1 + 91, "RECEIPT_RECEIVED", sub(pg, lease_id="seed-lease-pg"), {"kind": "VIEWED", "from": name("jamal")})

    # 2. Marcus asked Priya's group for the Backup server for 8 h: over policy, waiting for manual approval
    bk = ("cred-backup", "Backup server", "Medium")
    t2 = now - 40 * 60
    if me == "marcus":
        request("seed-req-bk", "out", "marcus", None, "grp-infra", bk, "CHG0030117",
                "Quarterly restore test, overnight window", 480, "pending", t2, target_name="Infrastructure custodians")
        ev(t2, "REQUEST_SENT", {"request_id": "seed-req-bk", "cred_name": bk[1]}, {"ticket": "CHG0030117"})
    if me in ("priya", "elena"):
        request("seed-req-bk", "in" if me == "priya" else "sync", "marcus", "priya", "grp-infra", bk, "CHG0030117",
                "Quarterly restore test, overnight window", 480, "pending", t2)
        if me == "priya":
            ev(t2 + 1, "REQUEST_RECEIVED", {"request_id": "seed-req-bk", "cred_name": bk[1]},
               {"from": name("marcus"), "decision": "manual", "minutes": 480})

    # 3. Jamal asked Sofia for her personal Expense tool login
    ex = (None, "Expense tool login", None)
    t3 = now - 25 * 60
    if me == "jamal":
        request("seed-req-ex", "out", "jamal", "sofia", None, ex, "RITM0020931", "Submitting conference expenses", 20,
                "pending", t3)
        ev(t3, "REQUEST_SENT", {"request_id": "seed-req-ex", "cred_name": ex[1]}, {"ticket": "RITM0020931"})
    if me == "sofia":
        request("seed-req-ex", "in", "jamal", "sofia", None, ex, "RITM0020931", "Submitting conference expenses", 20,
                "pending", t3)
        ev(t3 + 1, "REQUEST_RECEIVED", {"request_id": "seed-req-ex", "cred_name": ex[1]}, {"from": name("jamal")})

    # 4. Yesterday Priya approved AWS root for Marcus (Critical: manual); it expired -> rotation due
    aws = ("cred-aws-root", "AWS root account", "Critical")
    t4 = now - DAY - 3 * HOUR
    e4 = t4 + HOUR
    if me == "marcus":
        request("seed-req-aws", "out", "marcus", "priya", "grp-infra", aws, "INC0010388",
                "Billing alarm investigation needs root", 60, "approved", t4 - 300, t4, name("priya"),
                lease_id="seed-lease-aws", target_name="Infrastructure custodians")
        lease("seed-lease-aws", "in", aws, "grp-infra", "marcus", "priya", "seed-req-aws", "INC0010388", t4, e4,
              "expired", ended=e4)
        ev(t4 - 300, "REQUEST_SENT", {"request_id": "seed-req-aws", "cred_name": aws[1]}, {"ticket": "INC0010388"})
        ev(t4, "LEASE_RECEIVED", sub(aws, lease_id="seed-lease-aws"), {"from": name("priya")})
        ev(t4 + 120, "LEASE_VIEWED", sub(aws, lease_id="seed-lease-aws"))
        ev(e4, "LEASE_EXPIRED", sub(aws, lease_id="seed-lease-aws"), {"grantor": name("priya")})
    if me in ("priya", "elena"):
        d = "in" if me == "priya" else "sync"
        request("seed-req-aws", d, "marcus", "priya", "grp-infra", aws, "INC0010388",
                "Billing alarm investigation needs root", 60, "approved", t4 - 300, t4, name("priya"),
                lease_id="seed-lease-aws")
        lease("seed-lease-aws", "out" if me == "priya" else "sync", aws, "grp-infra", "marcus", "priya",
              "seed-req-aws", "INC0010388", t4, e4, "expired", ended=e4)
        db.insert(conn, "rotation_tasks", {"id": "seed-rot-aws", "cred_id": aws[0], "cred_name": aws[1],
                                           "reason": f"{name('marcus')} held this credential (checkout expired)",
                                           "status": "open", "created_at": e4})
        if me == "priya":
            ev(t4 - 299, "REQUEST_RECEIVED", {"request_id": "seed-req-aws", "cred_name": aws[1]},
               {"from": name("marcus"), "decision": "manual"})
            ev(t4, "REQUEST_APPROVED", sub(aws, request_id="seed-req-aws"), {"holder": name("marcus"), "minutes": 60})
            ev(t4, "LEASE_GRANTED", sub(aws, lease_id="seed-lease-aws"), {"holder": name("marcus")})
            ev(t4 + 121, "RECEIPT_RECEIVED", sub(aws, lease_id="seed-lease-aws"), {"kind": "VIEWED", "from": name("marcus")})
            ev(e4, "LEASE_EXPIRED", sub(aws, lease_id="seed-lease-aws"), {"holder": name("marcus")})
        ev(e4 + 1, "ROTATION_DUE", sub(aws), {"reason": "checkout expired"})

    # 5. Jamal (not a Security Tools member) asked Elena for SIEM admin: denied by policy
    siem = ("cred-siem", "SIEM admin", "High")
    t5 = now - 3 * DAY
    comment = "Group policy does not allow requests from non-members"
    if me == "jamal":
        request("seed-req-siem", "out", "jamal", "elena", "grp-sec", siem, "INC0010201", "Debug log forwarding", 30,
                "denied", t5, t5 + 1, "policy", comment, target_name="Security Tools custodians")
        ev(t5, "REQUEST_SENT", {"request_id": "seed-req-siem", "cred_name": siem[1]}, {"ticket": "INC0010201"})
        ev(t5 + 2, "REQUEST_DENIED", {"request_id": "seed-req-siem", "cred_name": siem[1]}, {"comment": comment})
    if me == "elena":
        request("seed-req-siem", "in", "jamal", "elena", "grp-sec", siem, "INC0010201", "Debug log forwarding", 30,
                "denied", t5, t5 + 1, "policy", comment)
        ev(t5 + 1, "REQUEST_RECEIVED", {"request_id": "seed-req-siem", "cred_name": siem[1]},
           {"from": name("jamal"), "decision": "deny"})
        ev(t5 + 1, "REQUEST_DENIED", {"request_id": "seed-req-siem", "cred_name": siem[1]},
           {"holder": name("jamal"), "comment": comment, "auto": True})
