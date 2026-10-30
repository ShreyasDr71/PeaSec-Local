"""Local-only REST API + static UI.

Defenses: Host header allow-list (blocks DNS rebinding), HttpOnly SameSite=Strict session
cookie, X-CSRF header on every mutation, idle auto-lock. Every route is `async def` so all
database access stays on the event-loop thread shared with the peer service.
"""
from __future__ import annotations

import asyncio
import hmac
from urllib.parse import urlsplit
import json
import os
import secrets
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import db, groups
from .engine import ACCOUNT_TYPES, CRITICALITIES, EngineError
from .vault import BadPassword, Locked

COOKIE = "p2psec_session"
PUBLIC = {"/api/status", "/api/unlock", "/api/setup"}
DEMO_PUBLIC = {"/api/demo", "/api/demo/start", "/api/demo/stop", "/api/demo/reset"}


def _strip(row: dict) -> dict:
    return {k: v for k, v in row.items() if not k.endswith("_ct") and not isinstance(v, bytes)}


def create_app(node, demo=None, base: str = "") -> FastAPI:
    """base: URL prefix this app is served under ("" for your own node, "/demo/<id>" for demo nodes)."""
    app = FastAPI(title="P2PSec", docs_url=None, redoc_url=None, openapi_url=None)
    cookie = COOKIE if not base else f"{COOKIE}_{node.settings.node_id}"
    public = PUBLIC | (DEMO_PUBLIC if demo else set())
    state = {"token": None, "csrf": None, "last": 0.0, "fails": 0}
    unlock_lock = asyncio.Lock()

    def end_session():
        state.update(token=None, csrf=None)

    def session_ok(request: Request) -> bool:
        tok = request.cookies.get(cookie)
        return bool(state["token"] and tok and hmac.compare_digest(tok, state["token"]) and node.personal_unlocked)

    def idle_check():
        if state["token"] and time.time() - state["last"] > node.settings.idle_lock_seconds:
            end_session()
            node.soft_lock()

    async def idle_loop():
        while True:
            await asyncio.sleep(15)
            idle_check()

    @app.on_event("startup")
    async def _start():
        app.state.idle = asyncio.get_running_loop().create_task(idle_loop())

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = (request.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
        if host not in node.settings.allowed_hosts:
            return JSONResponse({"detail": "Host not allowed"}, status_code=400)
        # path relative to this app's mount point (/demo/<id> for demo nodes), so the
        # sign-in and CSRF checks below apply no matter which prefix the request came through
        full, prefix = request.scope["path"], request.scope.get("root_path", "")
        path = full[len(prefix):] if prefix and full.startswith(prefix) else full
        if path.startswith("/api/") and request.method not in ("GET", "HEAD"):
            # A browser always sends Origin on cross-site POSTs; a page elsewhere must not drive this API,
            # not even /api/unlock. JSON-only bodies also rule out "simple" form/text posts.
            origin = request.headers.get("origin")
            if origin and (urlsplit(origin).hostname or "") not in node.settings.allowed_hosts:
                return JSONResponse({"detail": "Cross-origin request refused"}, status_code=403)
            ctype = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
            has_body = request.headers.get("content-length", "0") != "0" or "transfer-encoding" in request.headers
            if has_body and ctype != "application/json":
                return JSONResponse({"detail": "Content-Type must be application/json"}, status_code=415)
        if path.startswith("/api/") and path not in public:
            idle_check()
            if not session_ok(request):
                return JSONResponse({"detail": "Locked"}, status_code=401)
            if request.method not in ("GET", "HEAD"):
                if not hmac.compare_digest(request.headers.get("x-csrf", ""), state["csrf"] or "-"):
                    return JSONResponse({"detail": "CSRF token missing or wrong"}, status_code=403)
            state["last"] = time.time()
        try:
            response = await call_next(request)
        except EngineError as e:
            return JSONResponse({"detail": str(e)}, status_code=400)
        except Locked:
            return JSONResponse({"detail": "Vault is locked"}, status_code=423)
        except ValueError as e:
            return JSONResponse({"detail": str(e)}, status_code=400)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
            "font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        return response

    async def body(request: Request) -> dict:
        try:
            data = await request.json()
        except (json.JSONDecodeError, ValueError):
            data = {}
        if not isinstance(data, dict):
            raise HTTPException(400, "JSON object expected")
        return data

    def open_session() -> JSONResponse:
        state.update(token=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(32), last=time.time())
        resp = JSONResponse({"ok": True, "csrf": state["csrf"]})
        resp.set_cookie(cookie, state["token"], httponly=True, samesite="strict", path=base or "/")
        return resp

    E = lambda: node.engine
    conn = node.conn

    # --- session --------------------------------------------------------------

    @app.get("/api/status")
    async def status(request: Request):
        authed = session_ok(request)
        return {"initialized": node.initialized, "demo": node.settings.demo_mode, "node_id": node.settings.node_id,
                "profile": node.profile, "fpr": node.fpr, "unlocked": authed, "service_ready": node.service_ready,
                "peer_addr": node.advertise_addr, "csrf": state["csrf"] if authed else None,
                "demo_password": "p2psec-demo" if node.settings.demo_mode else None,
                "default_password": node.default_password, "base": base,
                "login_hint": (f"{node.login_name} / p2psec-demo" if node.settings.demo_mode
                               else "user / user" if node.default_password else None),
                "demo_available": demo is not None,
                "idle_lock_seconds": node.settings.idle_lock_seconds,
                "account_types": ACCOUNT_TYPES, "criticalities": CRITICALITIES}

    @app.post("/api/setup")
    async def setup(request: Request):
        if node.initialized:
            raise HTTPException(409, "already set up")
        b = await body(request)
        if not str(b.get("name", "")).strip():
            raise HTTPException(400, "name required")
        node.setup(str(b.get("password", "")), b)
        node.full_lock()
        await node.unlock(str(b["password"]))
        return open_session()

    @app.post("/api/unlock")
    async def unlock(request: Request):
        b = await body(request)
        async with unlock_lock:                       # one Argon2 run at a time
            started = time.monotonic()
            backoff = min(2 ** max(0, state["fails"] - 3), 30)
            # a wrong username fails exactly like a wrong password (same timing, same message)
            if not hmac.compare_digest(str(b.get("username", "")).strip().encode(), node.login_name.encode()):
                ok = False
                if node.audit:
                    node.audit.append("UNLOCK_FAILED", {"node": node.settings.node_id}, {"reason": "username"})
            else:
                try:
                    await node.unlock(str(b.get("password", "")))
                    ok = True
                except BadPassword:
                    ok = False
                except RuntimeError as e:
                    raise HTTPException(409, str(e))
            # same minimum duration for right and wrong answers, growing after repeated failures
            await asyncio.sleep(max(0.0, 1.0 + (0 if ok else backoff) - (time.monotonic() - started)))
            if not ok:
                state["fails"] += 1
                raise HTTPException(401, "Wrong username or password")
            state["fails"] = 0
        return open_session()

    @app.post("/api/lock")
    async def lock():
        end_session()
        node.soft_lock()
        return {"ok": True}

    @app.post("/api/lock-full")
    async def lock_full():
        end_session()
        node.full_lock()
        return {"ok": True}

    # --- dashboard --------------------------------------------------------------

    @app.get("/api/dashboard")
    async def dashboard():
        now = db.now()
        n = lambda sql, p=(): db.row(conn, sql, p)["c"]
        contacts = db.rows(conn, "SELECT fpr FROM contacts")
        return {
            "pending_approvals": n("SELECT count(*) c FROM requests WHERE direction='in' AND status='pending'"),
            "my_open_requests": n("SELECT count(*) c FROM requests WHERE direction='out' AND status='pending'"),
            "checked_out_to_me": n("SELECT count(*) c FROM leases WHERE direction='in' AND status='active'"),
            "checked_out_by_me": n("SELECT count(*) c FROM leases WHERE direction IN ('out','sync') AND status='active'"),
            "expiring_soon": n("SELECT count(*) c FROM leases WHERE status='active' AND expires_at < ?", (now + 3600,)),
            "rotations_due": n("SELECT count(*) c FROM rotation_tasks WHERE status='open'"),
            "alerts": n("SELECT count(*) c FROM alerts WHERE ack=0"),
            "peers_online": sum(node.peer.online(c["fpr"]) for c in contacts),
            "peers_total": len(contacts),
            "active_leases": db.rows(conn, "SELECT id, direction, cred_name, holder_name, grantor_name, expires_at, "
                                           "criticality FROM leases WHERE status='active' ORDER BY expires_at"),
            "recent": [_audit_row(r) for r in db.rows(conn, "SELECT * FROM audit ORDER BY seq DESC LIMIT 12")],
        }

    # --- credentials --------------------------------------------------------------

    def cred_view(c: dict) -> dict:
        v = _strip(c)
        v["open_rotation"] = bool(db.row(conn, "SELECT id FROM rotation_tasks WHERE cred_id=? AND status='open'",
                                         (c["id"],)))
        v["active_checkouts"] = db.row(conn, "SELECT count(*) c FROM leases WHERE cred_id=? AND status='active' "
                                             "AND direction IN ('out','sync')", (c["id"],))["c"]
        if c["group_id"]:
            head = groups.head_doc(conn, c["group_id"])
            v["group_name"] = head["name"] if head else ""
        return v

    @app.get("/api/credentials")
    async def credentials():
        return [cred_view(c) for c in db.rows(conn, "SELECT * FROM credentials ORDER BY scope DESC, name")]

    @app.post("/api/credentials")
    async def add_credential(request: Request):
        b = await body(request)
        if not str(b.get("name", "")).strip() or not str(b.get("secret", "")):
            raise HTTPException(400, "name and secret are required")
        _check_meta(b)
        cid = E().add_personal_credential(b, str(b["secret"]))
        return cred_view(db.row(conn, "SELECT * FROM credentials WHERE id=?", (cid,)))

    def _check_meta(b):
        if b.get("criticality") and b["criticality"] not in CRITICALITIES:
            raise HTTPException(400, "bad criticality")
        if b.get("account_type") and b["account_type"] not in ACCOUNT_TYPES:
            raise HTTPException(400, "bad account type")

    @app.get("/api/credentials/{cid}")
    async def credential(cid: str):
        c = db.row(conn, "SELECT * FROM credentials WHERE id=?", (cid,))
        if not c:
            raise HTTPException(404, "not found")
        return {"record": cred_view(c),
                "access": db.rows(conn, "SELECT id, direction, holder_name, grantor_name, ticket, granted_at, expires_at,"
                                        " status, ended_at FROM leases WHERE cred_id=? AND direction IN ('out','sync') "
                                        "ORDER BY granted_at DESC", (cid,)),
                "requests": [_strip(r) for r in db.rows(conn, "SELECT * FROM requests WHERE cred_id=? AND direction "
                                                              "IN ('in','sync') ORDER BY created_at DESC", (cid,))],
                "rotations": db.rows(conn, "SELECT * FROM rotation_tasks WHERE cred_id=? ORDER BY created_at DESC",
                                     (cid,)),
                "events": [_audit_row(r) for r in db.rows(conn, "SELECT * FROM audit WHERE subject LIKE ? "
                                                                "ORDER BY seq DESC LIMIT 50", (f'%"cred_id": "{cid}"%',))]}

    @app.put("/api/credentials/{cid}")
    async def edit_credential(cid: str, request: Request):
        b = await body(request)
        _check_meta(b)
        E().update_credential(cid, b, b.get("secret") or None)
        return {"ok": True}

    @app.delete("/api/credentials/{cid}")
    async def delete_credential(cid: str):
        E().delete_credential(cid)
        return {"ok": True}

    @app.post("/api/credentials/{cid}/reveal")
    async def reveal_credential(cid: str, request: Request):
        b = await body(request)
        action = "CRED_COPIED" if b.get("copy") else "CRED_VIEWED"
        return {"secret": E().reveal_credential(cid, action)}

    @app.post("/api/credentials/{cid}/rotate")
    async def rotate(cid: str, request: Request):
        b = await body(request)
        await node.act(E().rotate(cid, str(b.get("secret", ""))))
        return {"ok": True}

    # --- catalog & requests ---------------------------------------------------------

    @app.get("/api/catalog")
    async def catalog():
        out = []
        for head in groups.all_heads(conn):
            member = groups.is_member(head, node.fpr)
            for c in head["credentials"]:
                out.append(dict(c, group_id=head["group_id"], group_name=head["name"], policy=head["policy"],
                                is_custodian=groups.is_custodian(head, node.fpr), is_member=member,
                                custodians=[{"name": p["name"], "fpr": p["fpr"], "online": node.peer.online(p["fpr"])}
                                            for p in head["custodians"]]))
        people = [{"fpr": c["fpr"], "name": c["name"], "title": c["title"], "online": node.peer.online(c["fpr"])}
                  for c in db.rows(conn, "SELECT * FROM contacts ORDER BY name")]
        return {"credentials": out, "people": people}

    @app.get("/api/requests")
    async def my_requests():
        return [_strip(r) for r in db.rows(conn, "SELECT * FROM requests WHERE direction='out' ORDER BY created_at DESC")]

    @app.post("/api/requests")
    async def new_request(request: Request):
        b = await body(request)
        target = ({"group_id": b.get("group_id"), "cred_id": b.get("cred_id")} if b.get("group_id")
                  else {"owner_fpr": b.get("owner_fpr"), "description": b.get("description")})
        await node.act(E().create_request_out(target, str(b.get("ticket", "")), str(b.get("reason", "")),
                                              int(b.get("minutes") or 0)))
        return {"ok": True}

    @app.get("/api/approvals")
    async def approvals(state_: str = "pending"):
        where = "status='pending'" if state_ == "pending" else "status!='pending'"
        return [_strip(r) for r in db.rows(conn, f"SELECT * FROM requests WHERE direction IN ('in','sync') AND {where} "
                                                 "ORDER BY created_at DESC")]

    @app.post("/api/approvals/{rid}/approve")
    async def approve(rid: str, request: Request):
        b = await body(request)
        await node.act(E().approve(rid, b.get("minutes"), b.get("cred_id")))
        return {"ok": True}

    @app.post("/api/approvals/{rid}/deny")
    async def deny(rid: str, request: Request):
        b = await body(request)
        await node.act(E().deny(rid, str(b.get("comment", ""))))
        return {"ok": True}

    # --- checkouts ----------------------------------------------------------------

    @app.get("/api/leases/in")
    async def leases_in():
        return [_strip(r) for r in db.rows(conn, "SELECT * FROM leases WHERE direction='in' ORDER BY "
                                                 "status='active' DESC, expires_at DESC")]

    @app.post("/api/leases/in/{lid}/reveal")
    async def reveal_lease(lid: str, request: Request):
        b = await body(request)
        secret, outs = E().reveal_lease(lid)
        await node.act(outs)
        return {"secret": secret}

    @app.post("/api/leases/in/{lid}/checkin")
    async def checkin(lid: str):
        await node.act(E().checkin(lid))
        return {"ok": True}

    @app.get("/api/leases/out")
    async def leases_out():
        return [_strip(r) for r in db.rows(conn, "SELECT * FROM leases WHERE direction IN ('out','sync') ORDER BY "
                                                 "status='active' DESC, granted_at DESC")]

    @app.post("/api/leases/out/{lid}/revoke")
    async def revoke(lid: str):
        await node.act(E().revoke(lid))
        return {"ok": True}

    # --- groups -------------------------------------------------------------------

    def group_view(head: dict) -> dict:
        mark = lambda people: [dict({k: p[k] for k in ("fpr", "name", "title")}, online=node.peer.online(p["fpr"]),
                                    me=p["fpr"] == node.fpr) for p in people]
        return {"group_id": head["group_id"], "name": head["name"], "description": head["description"],
                "version": head["version"], "policy": head["policy"], "credentials": head["credentials"],
                "custodians": mark(head["custodians"]), "members": mark(head["members"]),
                "is_custodian": groups.is_custodian(head, node.fpr), "hash": groups.doc_hash(head)}

    @app.get("/api/groups")
    async def list_groups():
        return [group_view(h) for h in groups.all_heads(conn)]

    @app.get("/api/groups/{gid}")
    async def get_group(gid: str):
        head = groups.head_doc(conn, gid)
        if not head:
            raise HTTPException(404, "not found")
        v = group_view(head)
        v["history"] = [{"version": d["version"], "hash": groups.doc_hash(d),
                         "signed_by": [node.engine.name_of(s["fpr"]) for s in d["sigs"]]}
                        for d in groups.chain(conn, gid)]
        cred_ids = [c["cred_id"] for c in head["credentials"]]
        marks = ",".join("?" for _ in cred_ids) or "''"
        v["checkouts"] = db.rows(conn, f"SELECT id, cred_name, holder_name, grantor_name, status, granted_at, expires_at "
                                       f"FROM leases WHERE cred_id IN ({marks}) AND direction IN ('out','sync') "
                                       f"ORDER BY granted_at DESC LIMIT 50", cred_ids)
        return v

    @app.post("/api/groups")
    async def create_group(request: Request):
        b = await body(request)
        if not str(b.get("name", "")).strip():
            raise HTTPException(400, "name required")
        policy = {"auto_approve_members": bool(b.get("auto_approve_members", True)),
                  "allow_non_member_requests": bool(b.get("allow_non_member_requests", True)),
                  "max_lease_minutes": int(b.get("max_lease_minutes", 60)),
                  "default_lease_minutes": int(b.get("default_lease_minutes", 30))}
        gid, outs = E().create_group(str(b["name"]), str(b.get("description", "")), policy,
                                     list(b.get("custodians", [])), list(b.get("members", [])))
        await node.act(outs)
        return {"group_id": gid}

    @app.put("/api/groups/{gid}")
    async def update_group(gid: str, request: Request):
        b = await body(request)
        for c in b.get("credentials_add", []):
            _check_meta(c)
            if not c.get("name") or not c.get("secret"):
                raise HTTPException(400, "credential name and secret are required")
        await node.act(E().update_group(gid, b))
        return {"ok": True}

    # --- rotations ----------------------------------------------------------------

    @app.get("/api/rotations")
    async def rotations():
        return db.rows(conn, "SELECT * FROM rotation_tasks ORDER BY status='open' DESC, created_at DESC")

    @app.post("/api/rotations/{tid}/dismiss")
    async def dismiss(tid: str, request: Request):
        b = await body(request)
        await node.act(E().dismiss_rotation(tid, str(b.get("note", ""))))
        return {"ok": True}

    # --- peers & pairing ------------------------------------------------------------

    @app.get("/api/peers")
    async def peers():
        return [dict(_strip(c), online=node.peer.online(c["fpr"]))
                for c in db.rows(conn, "SELECT * FROM contacts ORDER BY name")]

    @app.get("/api/peers/nearby")
    async def nearby():
        return node.beacon.list() if node.beacon else []

    @app.delete("/api/peers/{fpr}")
    async def unpair(fpr: str):
        c = E().contact(fpr)
        if not c:
            raise HTTPException(404, "not paired")
        conn.execute("DELETE FROM contacts WHERE fpr=?", (fpr,))
        node.audit.append("UNPAIRED", {"peer_fpr": fpr, "peer_name": c["name"]})
        return {"ok": True}

    @app.post("/api/pair")
    async def pair(request: Request):
        b = await body(request)
        return node.peer.begin_pair(str(b.get("addr", "")).strip()).view()

    @app.get("/api/pair")
    async def pair_sessions():
        return [s.view() for s in node.peer.pair_sessions.values()
                if s.state not in ("paired", "failed") or s.role == "initiator"][-10:]

    @app.get("/api/pair/{sid}")
    async def pair_session(sid: str):
        s = node.peer.pair_sessions.get(sid)
        if not s:
            raise HTTPException(404, "no such pairing session")
        return s.view()

    @app.post("/api/pair/{sid}/accept")
    async def pair_accept(sid: str, request: Request):
        b = await body(request)
        if sid not in node.peer.pair_sessions:
            raise HTTPException(404, "no such pairing session")
        node.peer.accept_incoming(sid, bool(b.get("ok")))
        return {"ok": True}

    @app.post("/api/pair/{sid}/confirm")
    async def pair_confirm(sid: str, request: Request):
        b = await body(request)
        if sid not in node.peer.pair_sessions:
            raise HTTPException(404, "no such pairing session")
        node.peer.confirm(sid, bool(b.get("ok")), bool(b.get("demo_ack")))
        return {"ok": True}

    # --- audit --------------------------------------------------------------------

    @app.get("/api/audit")
    async def audit(event_type: str = "", q: str = "", limit: int = 100, offset: int = 0):
        where, params = [], []
        if event_type:
            where.append("event_type=?")
            params.append(event_type)
        if q:
            where.append("(subject LIKE ? OR details LIKE ?)")
            params += [f"%{q}%", f"%{q}%"]
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        limit = max(1, min(int(limit), 500))
        total = db.row(conn, f"SELECT count(*) c FROM audit {clause}", params)["c"]
        rows = db.rows(conn, f"SELECT * FROM audit {clause} ORDER BY seq DESC LIMIT ? OFFSET ?",
                       (*params, limit, max(0, int(offset))))
        types = [r["event_type"] for r in db.rows(conn, "SELECT DISTINCT event_type FROM audit ORDER BY event_type")]
        return {"total": total, "rows": [_audit_row(r) for r in rows], "event_types": types}

    @app.get("/api/audit/verify")
    async def verify():
        ok, bad = node.audit.verify()
        seq, head = node.audit.head()
        return {"ok": ok, "first_bad_seq": bad, "entries": seq, "head": head,
                "anchors": [dict(a, peer_name=node.engine.name_of(a["peer_fpr"]))
                            for a in db.rows(conn, "SELECT * FROM anchors")]}

    @app.get("/api/access")
    async def access():
        rows = db.rows(conn, "SELECT id, direction, cred_id, cred_name, criticality, holder_name, grantor_name, ticket, "
                             "granted_at, expires_at, status, ended_at FROM leases WHERE direction IN ('out','sync') "
                             "ORDER BY status='active' DESC, granted_at DESC")
        return rows

    @app.get("/api/alerts")
    async def alerts():
        return db.rows(conn, "SELECT * FROM alerts ORDER BY ts DESC")

    @app.post("/api/alerts/{aid}/ack")
    async def ack(aid: str):
        conn.execute("UPDATE alerts SET ack=1 WHERE id=?", (aid,))
        return {"ok": True}

    # --- settings -----------------------------------------------------------------

    @app.put("/api/settings/profile")
    async def profile(request: Request):
        b = await body(request)
        node.set_profile(b)
        return {"ok": True}

    @app.put("/api/settings/login")
    async def set_login(request: Request):
        b = await body(request)
        node.set_login(str(b.get("username", "")))
        return {"ok": True}

    # --- demo mode (only on your own node's app) -----------------------------------------

    if demo is not None:
        def demo_view():
            return {"running": demo.running, "users": demo.users(), "password": "p2psec-demo",
                    "tom_addr": demo.main.tom_advertise or None}

        @app.get("/api/demo")
        async def demo_status():
            return demo_view()

        @app.post("/api/demo/start")
        async def demo_start():
            await demo.start()
            return demo_view()

        @app.post("/api/demo/stop")
        async def demo_stop():
            await demo.stop(forget=True)
            return demo_view()

        @app.post("/api/demo/reset")
        async def demo_reset():
            await demo.reset()
            return demo_view()

    @app.post("/api/settings/password")
    async def password(request: Request):
        b = await body(request)
        try:
            node.change_password(str(b.get("old", "")), str(b.get("new", "")))
        except BadPassword:
            raise HTTPException(401, "Current password is wrong")
        return {"ok": True}

    # --- static UI ----------------------------------------------------------------

    static = os.environ.get("STATIC_DIR", os.path.join(os.path.dirname(__file__), "..", "static"))
    if os.path.isdir(static):
        app.mount("/assets", StaticFiles(directory=os.path.join(static, "assets")), name="assets")

        @app.get("/{path:path}")
        async def spa(path: str):
            f = os.path.join(static, path)
            if path and os.path.isfile(f) and os.path.realpath(f).startswith(os.path.realpath(static)):
                return FileResponse(f)
            return FileResponse(os.path.join(static, "index.html"))

    return app


def _audit_row(r: dict) -> dict:
    return {"seq": r["seq"], "ts": r["ts"], "actor_fpr": r["actor_fpr"], "event_type": r["event_type"],
            "subject": json.loads(r["subject"]), "details": json.loads(r["details"]), "hash": r["hash"]}


class Root:
    """ASGI entry point: /demo/<id>/... goes to that demo node's app, everything else to your node."""

    def __init__(self, main_app, demo=None):
        self.main_app, self.demo = main_app, demo

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "") if scope["type"] in ("http", "websocket") else ""
        if path.startswith("/demo/") and self.demo is not None:
            parts = path.split("/", 3)          # ["", "demo", "<id>", "rest"]
            nid = parts[2]
            sub = self.demo.apps.get(nid)
            if sub is None:
                return await JSONResponse({"detail": "Demo mode is off"}, status_code=404)(scope, receive, send)
            if len(parts) == 3:
                return await RedirectResponse(f"/demo/{nid}/")(scope, receive, send)
            # ASGI convention: keep the full path and declare the prefix as root_path
            scope = dict(scope, root_path=scope.get("root_path", "") + f"/demo/{nid}")
            return await sub(scope, receive, send)
        return await self.main_app(scope, receive, send)
