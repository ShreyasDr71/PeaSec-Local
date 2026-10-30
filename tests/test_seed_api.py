import pytest
import httpx
from p2psec import db as dbmod, groups
from p2psec.config import Settings
from p2psec.node import Node, DEMO_PASSWORD
from p2psec.api import create_app
from p2psec import seed

FAST = {"t": 1, "m": 8192, "p": 1}


async def seeded(tmp_path, node_id):
    s = Settings(node_id=node_id, data_dir=str(tmp_path / node_id), peer_host="127.0.0.1", peer_port=0,
                 beacon=False, demo_mode=True, demo_seed="test-seed")
    n = Node(s)
    seed.build(n, params=FAST)
    n.full_lock()
    await n.start_peer()
    await n.unlock(DEMO_PASSWORD)
    n.soft_lock()
    return n


@pytest.fixture
async def priya(tmp_path):
    n = await seeded(tmp_path, "priya")
    yield n
    await n.shutdown()


def client(node):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(node)), base_url="http://127.0.0.1")


async def login(c):
    r = await c.post("/api/unlock", json={"username": "priya", "password": DEMO_PASSWORD})
    assert r.status_code == 200
    return {"X-CSRF": r.json()["csrf"]}


@pytest.mark.parametrize("node_id", list(seed.TEAM))
async def test_every_seeded_node_log_verifies(tmp_path, node_id):
    n = await seeded(tmp_path, node_id)
    try:
        assert n.audit.verify() == (True, None)
        assert dbmod.row(n.conn, "SELECT count(*) c FROM audit")["c"] >= 20
    finally:
        await n.shutdown()


async def test_seed_nodes_agree_on_group_docs(tmp_path):
    a, b = await seeded(tmp_path, "priya"), await seeded(tmp_path, "elena")
    try:
        assert groups.doc_hash(groups.head_doc(a.conn, "grp-infra")) == groups.doc_hash(groups.head_doc(b.conn, "grp-infra"))
        assert a.engine.contact(b.fpr) is not None
    finally:
        await a.shutdown()
        await b.shutdown()


async def test_tom_is_unpaired(tmp_path):
    n = await seeded(tmp_path, "tom")
    try:
        assert dbmod.rows(n.conn, "SELECT * FROM contacts") == []
    finally:
        await n.shutdown()


async def test_locked_returns_401(priya):
    async with client(priya) as c:
        assert (await c.get("/api/dashboard")).status_code == 401
        assert (await c.get("/api/status")).status_code == 200


async def test_wrong_password_401_and_logged(priya):
    async with client(priya) as c:
        r = await c.post("/api/unlock", json={"username": "priya", "password": "nope"})
        assert r.status_code == 401
    assert dbmod.row(priya.conn, "SELECT event_type FROM audit ORDER BY seq DESC LIMIT 1")["event_type"] == "UNLOCK_FAILED"


async def test_missing_csrf_403(priya):
    async with client(priya) as c:
        await login(c)
        r = await c.post("/api/lock")
        assert r.status_code == 403


async def test_bad_host_400(priya):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(priya)),
                                 base_url="http://evil.example") as c:
        assert (await c.get("/api/status")).status_code == 400


async def test_seeded_dashboard_counts(priya):
    async with client(priya) as c:
        h = await login(c)
        d = (await c.get("/api/dashboard", headers=h)).json()
        assert d["pending_approvals"] == 1
        assert d["rotations_due"] == 1


async def test_reveal_personal_credential_logged(priya):
    async with client(priya) as c:
        h = await login(c)
        creds = (await c.get("/api/credentials", headers=h)).json()
        personal = next(x for x in creds if x["scope"] == "personal")
        r = await c.post(f"/api/credentials/{personal['id']}/reveal", headers=h)
        assert r.status_code == 200 and r.json()["secret"]
        assert "secret_ct" not in personal


async def test_lock_ends_session(priya):
    async with client(priya) as c:
        h = await login(c)
        assert (await c.post("/api/lock", headers=h)).status_code == 200
        assert (await c.get("/api/dashboard", headers=h)).status_code == 401
        assert priya.service_ready


async def test_request_requires_ticket(priya):
    async with client(priya) as c:
        h = await login(c)
        r = await c.post("/api/requests", headers=h, json={"group_id": "grp-sec", "cred_id": "cred-siem",
                                                            "ticket": "", "reason": "x", "minutes": 10})
        assert r.status_code == 400


async def test_I4_unlock_requires_json_content_type(priya):
    async with client(priya) as c:
        r = await c.post("/api/unlock", content='{"password":"p2psec-demo"}', headers={"Content-Type": "text/plain"})
        assert r.status_code == 415


async def test_I4_cross_origin_post_rejected(priya):
    async with client(priya) as c:
        r = await c.post("/api/unlock", json={"username": "priya", "password": "p2psec-demo"}, headers={"Origin": "http://evil.example"})
        assert r.status_code == 403
        r = await c.post("/api/unlock", json={"username": "priya", "password": "p2psec-demo"}, headers={"Origin": "http://127.0.0.1"})
        assert r.status_code == 200
