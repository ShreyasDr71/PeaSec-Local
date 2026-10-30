import pytest
from p2psec import db as dbmod, groups
from p2psec.engine import decide, EngineError
from tests.helpers import make_engine, pair_all, setup_group, route, cred, POLICY


@pytest.fixture
def team(tmp_path):
    priya, elena, jamal, tom = (make_engine(tmp_path, n) for n in ("priya", "elena", "jamal", "tom"))
    pair_all([priya, elena, jamal, tom])
    return priya, elena, jamal, tom


def lease_in(eng):
    return dbmod.rows(eng.conn, "SELECT * FROM leases WHERE direction='in'")


def request_from(jamal, priya, elena, cid="c1", minutes=30):
    outs = jamal.create_request_out({"group_id": "g1", "cred_id": cid}, "INC0010001", "patching", minutes)
    route(outs, jamal, [priya, elena, jamal])


@pytest.mark.parametrize("member,policy,minutes,crit,expected", [
    (True, POLICY, 30, "High", "auto"),
    (True, POLICY, 300, "High", "manual"),
    (True, POLICY, 30, "Critical", "manual"),
    (False, POLICY, 30, "Low", "manual"),
    (False, dict(POLICY, allow_non_member_requests=False), 30, "Low", "deny"),
    (True, dict(POLICY, auto_approve_members=False), 30, "Low", "manual"),
])
def test_decide_matrix(member, policy, minutes, crit, expected):
    assert decide(member, policy, minutes, crit) == expected


def test_auto_approve_flow(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena)
    [lease] = lease_in(jamal)
    assert lease["status"] == "active" and lease["grantor_fpr"] == priya.fpr
    assert jamal.reveal_lease(lease["id"])[0] == "S3cr3t!"
    out = dbmod.row(priya.conn, "SELECT * FROM leases WHERE direction='out'")
    assert out["holder_fpr"] == jamal.fpr and out["status"] == "active"
    events = [r["event_type"] for r in dbmod.rows(priya.conn, "SELECT event_type FROM audit")]
    assert "REQUEST_AUTO_APPROVED" in events and "RECEIPT_RECEIVED" in events
    req = dbmod.row(jamal.conn, "SELECT * FROM requests WHERE direction='out'")
    assert req["status"] == "approved"


def test_custodian_sync_shares_lease(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena)
    synced = dbmod.rows(elena.conn, "SELECT * FROM leases WHERE direction='sync'")
    assert len(synced) == 1 and synced[0]["holder_fpr"] == jamal.fpr and synced[0]["secret_ct"] is None


def test_request_while_soft_locked(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    priya.vault.soft_lock()
    jamal.vault.soft_lock()
    request_from(jamal, priya, elena)
    assert lease_in(jamal)[0]["status"] == "active"


def test_critical_needs_manual_approval(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred(criticality="Critical")])
    request_from(jamal, priya, elena)
    assert lease_in(jamal) == []
    pending = dbmod.row(priya.conn, "SELECT * FROM requests WHERE direction='in'")
    assert pending["status"] == "pending"
    route(priya.approve(pending["id"], 20), priya, [priya, elena, jamal])
    assert lease_in(jamal)[0]["status"] == "active"


def test_non_member_denied_when_policy_forbids(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()], policy=dict(POLICY, allow_non_member_requests=False))
    groups.store(tom.conn, groups.head_doc(priya.conn, "g1"))
    outs = tom.create_request_out({"group_id": "g1", "cred_id": "c1"}, "INC1", "why", 30)
    route(outs, tom, [priya, elena, tom])
    req = dbmod.row(tom.conn, "SELECT * FROM requests WHERE direction='out'")
    assert req["status"] == "denied"


def test_duplicate_request_extends(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena, minutes=10)
    first = lease_in(jamal)[0]["expires_at"]
    request_from(jamal, priya, elena, minutes=60)
    leases = lease_in(jamal)
    assert len(leases) == 1 and leases[0]["expires_at"] > first
    assert len(dbmod.rows(priya.conn, "SELECT * FROM leases WHERE direction='out'")) == 1


def test_expired_lease_swept_on_boot(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena)
    jamal.conn.execute("UPDATE leases SET expires_at=1")
    outs = jamal.sweep()
    lease = lease_in(jamal)[0]
    assert lease["status"] == "expired" and lease["secret_ct"] is None
    route(outs, jamal, [priya, elena, jamal])
    assert dbmod.row(priya.conn, "SELECT status FROM leases WHERE direction='out'")["status"] == "expired"
    assert dbmod.row(priya.conn, "SELECT status FROM rotation_tasks")["status"] == "open"


def test_checkin_raises_rotation_for_high(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred(criticality="High")])
    request_from(jamal, priya, elena)
    route(jamal.checkin(lease_in(jamal)[0]["id"]), jamal, [priya, elena, jamal])
    assert lease_in(jamal)[0]["secret_ct"] is None
    task = dbmod.row(priya.conn, "SELECT * FROM rotation_tasks")
    assert task["status"] == "open" and task["cred_id"] == "c1"
    assert dbmod.row(elena.conn, "SELECT * FROM rotation_tasks")["status"] == "open"


def test_revoke_deletes_on_holder(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena)
    lease_id = dbmod.row(priya.conn, "SELECT id FROM leases WHERE direction='out'")["id"]
    route(priya.revoke(lease_id), priya, [priya, elena, jamal])
    lease = lease_in(jamal)[0]
    assert lease["status"] == "revoked" and lease["secret_ct"] is None


def test_cocustodian_can_revoke(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena)
    lease_id = dbmod.row(elena.conn, "SELECT id FROM leases WHERE direction='sync'")["id"]
    route(elena.revoke(lease_id), elena, [priya, elena, jamal])
    assert lease_in(jamal)[0]["status"] == "revoked"


def test_rotate_closes_tasks_and_syncs_secret(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    request_from(jamal, priya, elena)
    route(jamal.checkin(lease_in(jamal)[0]["id"]), jamal, [priya, elena, jamal])
    route(priya.rotate("c1", "N3w-Secret"), priya, [priya, elena, jamal])
    assert dbmod.row(priya.conn, "SELECT status FROM rotation_tasks")["status"] == "done"
    assert dbmod.row(elena.conn, "SELECT status FROM rotation_tasks")["status"] == "done"
    assert elena.credential_secret("c1") == "N3w-Secret"


def test_pending_request_expires_after_24h(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred(criticality="Critical")])
    request_from(jamal, priya, elena)
    priya.conn.execute("UPDATE requests SET created_at=created_at-90000")
    priya.sweep()
    assert dbmod.row(priya.conn, "SELECT status FROM requests")["status"] == "expired"


def test_unsolicited_lease_rejected(team):
    priya, elena, jamal, tom = team
    with pytest.raises(EngineError):
        jamal.handle("lease", {"lease_id": "x", "request_id": "nope", "cred_id": "c", "cred_name": "c",
                               "secret": "s", "expires_at": 9e12, "granted_at": 1}, priya.fpr)


def test_personal_request_manual_flow(team):
    priya, elena, jamal, tom = team
    cid = priya.add_personal_credential({"name": "Grafana personal", "url": "", "username": "priya",
                                         "account_type": "Application", "criticality": "Low"}, "pw!")
    outs = jamal.create_request_out({"owner_fpr": priya.fpr, "description": "Grafana login"}, "RITM1", "dash", 15)
    route(outs, jamal, [priya, jamal])
    req = dbmod.row(priya.conn, "SELECT * FROM requests WHERE direction='in'")
    assert req["status"] == "pending"
    route(priya.approve(req["id"], 15, cred_id=cid), priya, [priya, jamal])
    lease = lease_in(jamal)[0]
    assert jamal.reveal_lease(lease["id"])[0] == "pw!"


def test_spoofed_body_fpr_rejected(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    with pytest.raises(EngineError, match="identity"):
        priya.handle("request", {"request_id": "r", "group_id": "g1", "cred_id": "c1", "minutes": 5,
                                 "ticket": "t", "reason": "r", "requester_fpr": jamal.fpr}, tom.fpr)


def test_request_from_unpaired_rejected(team, tmp_path):
    priya, elena, jamal, tom = team
    stranger = make_engine(tmp_path, "stranger")
    with pytest.raises(EngineError):
        priya.handle("request", {"request_id": "r", "group_id": "g1", "cred_id": "c1", "minutes": 5,
                                 "ticket": "t", "reason": "r"}, stranger.fpr)


def test_group_update_pushed_and_accepted(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    outs = priya.update_group("g1", {"members_add": [tom.fpr]})
    route(outs, priya, [priya, elena, jamal, tom])
    head = groups.head_doc(tom.conn, "g1")
    assert head["version"] == 2 and groups.is_member(head, tom.fpr)
    assert groups.head_doc(jamal.conn, "g1")["version"] == 2


def test_added_group_credential_reaches_cocustodian(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    outs = priya.update_group("g1", {"credentials_add": [{"name": "Backup", "username": "svc", "url": "",
                                                          "account_type": "Service Account",
                                                          "criticality": "Medium", "secret": "B@ck"}]})
    route(outs, priya, [priya, elena, jamal])
    new_id = groups.head_doc(elena.conn, "g1")["credentials"][-1]["cred_id"]
    assert elena.credential_secret(new_id) == "B@ck"


# --- final-review fixes -------------------------------------------------------------

def test_C1_rogue_group_cannot_reference_other_groups_credential(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred(criticality="Critical")])
    rogue = groups.make_genesis("evil", "Evil", "", [groups.person("tom", tom.identity), groups.person("priya", priya.identity)],
                                [], dict(POLICY), [{"cred_id": "c1", "name": "x", "url": "", "username": "",
                                                    "account_type": "Root", "criticality": "Low"}], [tom.identity])
    route([__import__("p2psec.engine", fromlist=["Out"]).Out([priya.fpr], "group_docs", {"group_id": "evil", "docs": [rogue]})],
          tom, [priya, tom])
    groups.store(tom.conn, rogue)
    outs = tom.create_request_out({"group_id": "evil", "cred_id": "c1"}, "INC1", "steal", 5)
    with pytest.raises(EngineError):
        priya.handle(outs[0].type, outs[0].body, tom.fpr)
    assert lease_in(tom) == []


def test_C2_sync_rejects_unknown_columns(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    bad = {"id": "x", "status) VALUES ('a') --": 1}
    with pytest.raises(EngineError):
        elena.handle("sync", {"kind": "request", "group_id": "g1", "row": bad}, priya.fpr)


def test_C2_sync_cannot_forge_request_from_unpaired_requester(team, tmp_path):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    stranger = make_engine(tmp_path, "stranger2")
    row = {"id": "forged", "requester_fpr": stranger.fpr, "requester_name": "Jamal Okafor", "group_id": "g1",
           "cred_id": "c1", "cred_name": "cred c1", "ticket": "t", "reason": "r", "minutes": 5, "status": "pending",
           "created_at": 1.0}
    with pytest.raises(EngineError):
        elena.handle("sync", {"kind": "request", "group_id": "g1", "row": row}, priya.fpr)


def test_C2_synced_request_name_comes_from_local_contact(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    row = {"id": "r1", "requester_fpr": tom.fpr, "requester_name": "Jamal Okafor", "group_id": "g1",
           "cred_id": "c1", "cred_name": "anything", "ticket": "t", "reason": "r", "minutes": 5, "status": "pending",
           "created_at": 1.0}
    elena.handle("sync", {"kind": "request", "group_id": "g1", "row": row}, priya.fpr)
    got = dbmod.row(elena.conn, "SELECT * FROM requests WHERE id='r1'")
    assert got["requester_name"] == "tom" and got["cred_name"] == "cred c1"


def test_C2_sync_cannot_touch_other_groups_or_incoming_leases(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    setup_group([elena], [priya], [cred("c2")], group_id="g2")
    route(priya.create_request_out({"group_id": "g2", "cred_id": "c2"}, "INC", "r", 30), priya, [priya, elena])
    lid = lease_in(priya)[0]["id"]
    row = dict(dbmod.row(priya.conn, "SELECT * FROM leases WHERE id=?", (lid,)), status="revoked", group_id="g1")
    row.pop("secret_ct"); row.pop("direction")
    with pytest.raises(EngineError):
        priya.handle("sync", {"kind": "lease", "group_id": "g1", "row": row}, elena.fpr)
    assert lease_in(priya)[0]["status"] == "active"


def test_I1_revoke_before_lease_tombstones_it(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    outs = jamal.create_request_out({"group_id": "g1", "cred_id": "c1"}, "INC", "r", 30)
    lease_outs = priya.handle(outs[0].type, outs[0].body, jamal.fpr)
    lease_msg = next(o for o in lease_outs if o.type == "lease")
    lid = lease_msg.body["lease_id"]
    revoke = next(o for o in priya.revoke(lid) if o.type == "revoke")
    jamal.handle("revoke", revoke.body, priya.fpr)          # arrives first
    with pytest.raises(EngineError):
        jamal.handle("lease", lease_msg.body, priya.fpr)    # late lease is refused
    assert lease_in(jamal) == []


def test_I2_second_request_to_other_custodian_extends(team):
    priya, elena, jamal, tom = team
    setup_group([priya, elena], [jamal], [cred()])
    route(jamal.create_request_out({"group_id": "g1", "cred_id": "c1"}, "INC", "r", 10), jamal, [priya, elena, jamal])
    first = lease_in(jamal)[0]
    outs = jamal.create_request_out({"group_id": "g1", "cred_id": "c1"}, "INC", "r", 60)
    route(elena.handle(outs[0].type, outs[0].body, jamal.fpr), elena, [priya, elena, jamal])
    leases = lease_in(jamal)
    assert len(leases) == 1 and leases[0]["id"] == first["id"] and leases[0]["expires_at"] > first["expires_at"]
