"""Single-user default node (user/user) and the opt-in in-process demo team."""
import asyncio
import pytest
import httpx
from p2psec import db as dbmod
from p2psec.config import Settings
from p2psec.node import Node
from p2psec.demo import DemoTeam, TEAM_IDS
from p2psec.api import create_app, Root

FAST = {"t": 1, "m": 8192, "p": 1}


def settings(tmp_path, **kw):
    return Settings(node_id="me", data_dir=str(tmp_path / "data"), peer_host="127.0.0.1", peer_port=0,
                    beacon=False, **kw)


@pytest.fixture
async def main(tmp_path):
    n = Node(settings(tmp_path))
    n.vault_params = FAST
    await n.boot()
    yield n
    await n.shutdown()


def client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1")


async def login(c, username, password, base=""):
    r = await c.post(f"{base}/api/unlock", json={"username": username, "password": password})
    return r


# --- default single-user node ---------------------------------------------------------

async def test_fresh_node_has_default_login_and_no_seed(main):
    assert main.initialized
    assert dbmod.rows(main.conn, "SELECT * FROM contacts") == []
    assert dbmod.rows(main.conn, "SELECT * FROM credentials") == []
    assert dbmod.rows(main.conn, "SELECT * FROM group_docs") == []
    async with client(create_app(main)) as c:
        st = (await c.get("/api/status")).json()
        assert st["default_password"] is True and st["login_hint"] == "user / user"
        assert st["demo"] is False
        assert (await login(c, "user", "user")).status_code == 200


async def test_wrong_username_rejected_even_with_right_password(main):
    async with client(create_app(main)) as c:
        assert (await login(c, "admin", "user")).status_code == 401
        assert not main.personal_unlocked


async def test_changing_password_clears_default_flag(main):
    async with client(create_app(main)) as c:
        h = {"X-CSRF": (await login(c, "user", "user")).json()["csrf"]}
        r = await c.post("/api/settings/password", headers=h, json={"old": "user", "new": "a-much-better-passphrase"})
        assert r.status_code == 200
        st = (await c.get("/api/status")).json()
        assert st["default_password"] is False and st["login_hint"] is None
        r = await c.put("/api/settings/login", headers=h, json={"username": "shreyas"})
        assert r.status_code == 200
        await c.post("/api/lock", headers=h)
        assert (await login(c, "user", "a-much-better-passphrase")).status_code == 401
        assert (await login(c, "shreyas", "a-much-better-passphrase")).status_code == 200


# --- demo team ------------------------------------------------------------------------

@pytest.fixture
async def team(main, tmp_path):
    t = DemoTeam(main.settings, params=FAST, port_base=0)
    yield t
    await t.stop()


async def test_demo_is_off_until_started(main, team):
    assert not team.running
    root = Root(create_app(main, demo=team), team)
    async with client(root) as c:
        assert (await c.get("/demo/priya/api/status")).status_code == 404
        assert (await c.get("/api/demo")).json()["running"] is False


async def test_demo_start_runs_six_seeded_nodes_that_talk(team):
    await team.start()
    assert sorted(team.nodes) == sorted(TEAM_IDS)
    jamal, marcus = team.nodes["jamal"], team.nodes["marcus"]
    assert all(n.service_ready for n in team.nodes.values())
    outs = jamal.engine.create_request_out({"group_id": "grp-db", "cred_id": "cred-redis"}, "INC1", "flush", 15)
    await jamal.peer.send_outs(outs)
    for _ in range(200):
        if dbmod.row(jamal.conn, "SELECT * FROM leases WHERE direction='in' AND cred_id='cred-redis'"):
            break
        await asyncio.sleep(0.02)
    assert dbmod.row(jamal.conn, "SELECT status FROM leases WHERE cred_id='cred-redis'")["status"] == "active"


async def test_demo_reset_restores_seed(team):
    await team.start()
    priya = team.nodes["priya"]
    req = dbmod.row(priya.conn, "SELECT id FROM requests WHERE direction='in' AND status='pending'")
    priya.engine.deny(req["id"], "test")
    await team.reset()
    priya = team.nodes["priya"]
    assert dbmod.row(priya.conn, "SELECT count(*) c FROM requests WHERE direction='in' AND status='pending'")["c"] == 1


async def test_demo_routes_and_scoped_cookies(main, team):
    root = Root(create_app(main, demo=team), team)
    async with client(root) as c:
        r = await c.post("/api/demo/start", json={})
        assert r.status_code == 200
        st = (await c.get("/demo/priya/api/status")).json()
        assert st["node_id"] == "priya" and st["demo"] is True and st["login_hint"] == "priya / p2psec-demo"
        r = await login(c, "priya", "p2psec-demo", base="/demo/priya")
        assert r.status_code == 200
        cookie = r.headers["set-cookie"]
        assert "p2psec_session_priya=" in cookie and "Path=/demo/priya" in cookie
        main_status = (await c.get("/api/status")).json()
        assert main_status["node_id"] == "me" and main_status["unlocked"] is False
        users = (await c.get("/api/demo")).json()["users"]
        assert {u["id"] for u in users} == set(TEAM_IDS) and users[0]["url"].startswith("/demo/")


async def test_demo_start_rejects_cross_site(main, team):
    root = Root(create_app(main, demo=team), team)
    async with client(root) as c:
        r = await c.post("/api/demo/start", json={}, headers={"Origin": "http://evil.example"})
        assert r.status_code == 403
        assert not team.running


async def test_demo_user_page_assets_and_auth(main, team):
    import os, glob
    root = Root(create_app(main, demo=team), team)
    async with client(root) as c:
        await c.post("/api/demo/start", json={})
        assert (await c.get("/demo/priya/api/dashboard")).status_code == 401     # still behind sign-in
        assert (await c.get("/demo/priya/")).status_code == 200
        dist = os.path.join(os.path.dirname(__file__), "..", "static", "assets")
        asset = os.path.basename(sorted(glob.glob(os.path.join(dist, "*.js")))[0])
        assert (await c.get(f"/demo/priya/assets/{asset}")).status_code == 200
        assert (await c.get("/demo/priya/favicon.svg")).status_code == 200
