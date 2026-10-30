"""Real TCP between in-process nodes."""
import asyncio
import pytest
from p2psec import db as dbmod, groups, peer as peermod
from p2psec.config import Settings
from p2psec.node import Node

FAST = {"t": 1, "m": 8192, "p": 1}


async def make_node(tmp_path, name, demo=False):
    s = Settings(node_id=name, data_dir=str(tmp_path / name), peer_host="127.0.0.1", peer_port=0,
                 beacon=False, demo_mode=demo)
    n = Node(s)
    n.setup("password1", {"name": name.title(), "title": "Engineer", "dept": "IT"}, params=FAST)
    await n.start_peer()
    return n


async def until(cond, timeout=5.0):
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("condition not met in time")


async def pair(a, b, a_ok=True, b_ok=True):
    sa = a.peer.begin_pair(b.advertise_addr)
    await until(lambda: any(s.state == "incoming" for s in b.peer.pair_sessions.values()))
    sb = next(iter(b.peer.pair_sessions.values()))
    b.peer.accept_incoming(sb.id, True)
    await until(lambda: sa.state == "compare_codes" and sb.state == "compare_codes")
    assert sa.sas == sb.sas
    a.peer.confirm(sa.id, a_ok, demo_ack=True)
    b.peer.confirm(sb.id, b_ok, demo_ack=True)
    await until(lambda: sa.state in ("paired", "failed") and sb.state in ("paired", "failed"))
    return sa, sb


@pytest.fixture
async def ab(tmp_path):
    a, b = await make_node(tmp_path, "priya"), await make_node(tmp_path, "jamal")
    yield a, b
    await a.shutdown()
    await b.shutdown()


async def test_pairing_over_tcp(ab):
    a, b = ab
    sa, sb = await pair(a, b)
    assert sa.state == sb.state == "paired"
    assert a.engine.contact(b.fpr)["name"] == "Jamal"
    assert b.engine.contact(a.fpr)["name"] == "Priya"
    assert a.engine.contact(b.fpr)["addr"] == b.advertise_addr


async def test_pairing_rejected_when_codes_disputed(ab):
    a, b = ab
    sa, sb = await pair(a, b, b_ok=False)
    assert sa.state == "failed" and sb.state == "failed"
    assert a.engine.contact(b.fpr) is None and b.engine.contact(a.fpr) is None


async def test_declined_pair_request(ab):
    a, b = ab
    sa = a.peer.begin_pair(b.advertise_addr)
    await until(lambda: any(s.state == "incoming" for s in b.peer.pair_sessions.values()))
    b.peer.accept_incoming(next(iter(b.peer.pair_sessions)), False)
    await until(lambda: sa.state == "failed")
    assert "declined" in sa.error


async def test_demo_peer_needs_acknowledgement(tmp_path):
    a = await make_node(tmp_path, "real")
    d = await make_node(tmp_path, "tom", demo=True)
    try:
        sa = a.peer.begin_pair(d.advertise_addr)
        await until(lambda: any(s.state == "incoming" for s in d.peer.pair_sessions.values()))
        d.peer.accept_incoming(next(iter(d.peer.pair_sessions)), True)
        await until(lambda: sa.state == "compare_codes")
        assert sa.demo_warning
        with pytest.raises(ValueError):
            a.peer.confirm(sa.id, True)
    finally:
        await a.shutdown()
        await d.shutdown()


async def test_group_request_and_auto_checkout_over_tcp(ab):
    a, b = ab
    await pair(a, b)
    gid, outs = a.engine.create_group("Databases", "", {"auto_approve_members": True, "max_lease_minutes": 120,
                                                        "default_lease_minutes": 30,
                                                        "allow_non_member_requests": True}, [], [b.fpr])
    await a.peer.send_outs(outs)
    await a.peer.send_outs(a.engine.update_group(gid, {"credentials_add": [
        {"name": "Prod PostgreSQL", "username": "pg_admin", "url": "", "account_type": "Database",
         "criticality": "High", "secret": "pg-secret"}]}))
    head = groups.head_doc(b.conn, gid)
    assert head and head["version"] == 2
    await b.peer.send_outs(b.engine.create_request_out({"group_id": gid, "cred_id": head["credentials"][0]["cred_id"]},
                                                       "INC0042", "migration", 30))
    await until(lambda: dbmod.row(b.conn, "SELECT * FROM leases WHERE direction='in'") is not None)
    lease = dbmod.row(b.conn, "SELECT * FROM leases WHERE direction='in'")
    assert b.engine.reveal_lease(lease["id"])[0] == "pg-secret"
    assert dbmod.row(a.conn, "SELECT * FROM anchors WHERE peer_fpr=?", (b.fpr,)) is not None


async def test_outbox_redelivers(ab):
    a, b = ab
    await pair(a, b)
    await a.peer.stop()
    await b.peer.send_outs(b.engine.create_request_out({"owner_fpr": a.fpr, "description": "Grafana"},
                                                       "RITM9", "dashboards", 15))
    assert dbmod.row(b.conn, "SELECT count(*) n FROM outbox")["n"] == 1
    _, port = a.advertise_addr.rsplit(":", 1)
    await a.peer.start("127.0.0.1", int(port))
    await b.peer.flush_outbox()
    assert dbmod.row(b.conn, "SELECT count(*) n FROM outbox")["n"] == 0
    assert dbmod.row(a.conn, "SELECT status FROM requests WHERE direction='in'")["status"] == "pending"


async def test_outbox_is_encrypted_at_rest(ab):
    a, b = ab
    await pair(a, b)
    await a.peer.stop()
    await b.peer.send_outs(b.engine.create_request_out({"owner_fpr": a.fpr, "description": "VERY-UNIQUE-TEXT"},
                                                       "RITM9", "dashboards", 15))
    body = dbmod.row(b.conn, "SELECT body FROM outbox")["body"]
    assert "VERY-UNIQUE-TEXT" not in body


async def test_fully_locked_node_is_offline(ab):
    a, b = ab
    await pair(a, b)
    b.full_lock()
    assert not await a.peer._send(b.fpr, "ping", {})


async def test_peer_rejection_ends_other_side_immediately(ab):
    a, b = ab
    sa = a.peer.begin_pair(b.advertise_addr)
    await until(lambda: any(s.state == "incoming" for s in b.peer.pair_sessions.values()))
    sb = next(iter(b.peer.pair_sessions.values()))
    b.peer.accept_incoming(sb.id, True)
    await until(lambda: sa.state == "compare_codes" and sb.state == "compare_codes")
    a.peer.confirm(sa.id, False)
    await until(lambda: sb.state == "failed", timeout=3)
    assert "do not match" in sb.error


async def test_I3_beacon_does_not_overwrite_paired_address(ab):
    from p2psec.discovery import Beacon
    a, b = ab
    await pair(a, b)
    beacon = Beacon(a)
    beacon.on_beacon(b.fpr, "Jamal", "10.9.9.9:1", False)
    assert a.engine.contact(b.fpr)["addr"] == b.advertise_addr


async def test_I1_send_queues_behind_pending_outbox(ab):
    a, b = ab
    await pair(a, b)
    a.peer.queue(b.fpr, "ping", {})
    await a.peer.send_outs([__import__("p2psec.engine", fromlist=["Out"]).Out([b.fpr], "ping", {})])
    assert dbmod.row(a.conn, "SELECT count(*) n FROM outbox")["n"] == 2


async def test_unreachable_pair_address_explains_what_to_check(tmp_path):
    a = await make_node(tmp_path, "lonely")
    try:
        import socket
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()   # nothing listens here
        sess = a.peer.begin_pair(f"127.0.0.1:{port}")
        await until(lambda: sess.state == "failed")
        assert "Could not reach 127.0.0.1:" in sess.error and "start script" in sess.error
    finally:
        await a.shutdown()


@pytest.mark.parametrize("given,expected", [
    ("192.168.1.20", "192.168.1.20:7600"),
    (" 192.168.1.20 ", "192.168.1.20:7600"),
    ("192.168.1.20:7606", "192.168.1.20:7606"),
    ("laptop.local", "laptop.local:7600"),
    ("fe80::1", "[fe80::1]:7600"),
    ("[fe80::1]:7606", "[fe80::1]:7606"),
])
def test_pair_address_defaults_to_peer_port(given, expected):
    assert peermod.normalize_addr(given) == expected


@pytest.mark.parametrize("bad", ["", ":7600", "host:port", "1.2.3.4:99999"])
def test_bad_pair_address_is_refused(bad):
    with pytest.raises(ValueError, match="IP address"):
        peermod.normalize_addr(bad)


def test_default_advertised_address_is_an_ip_not_the_hostname(tmp_path, monkeypatch):
    import ipaddress
    import socket
    from p2psec import node as nodemod
    monkeypatch.setattr(socket, "gethostname", lambda: "LAPTOP-SECRET")
    n = Node(Settings(node_id="x", data_dir=str(tmp_path / "x"), beacon=False))
    host, port = peermod.split_addr(n.advertise_addr)
    assert "LAPTOP-SECRET" not in n.advertise_addr
    ipaddress.ip_address(host)                       # raises if it is not an IP literal
    assert port == 7600
    assert nodemod.lan_ip() == host
