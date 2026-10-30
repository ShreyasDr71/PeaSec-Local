"""Peer service: TCP server/client for pairing and Noise sessions, outbox, presence."""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid

from . import db, framing
from .channel import ChannelError, accept_channel, open_channel
from .engine import EngineError, Out
from .pairing import PairingError, PairingInitiator, PairingResponder

log = logging.getLogger("p2psec.peer")
PAIR_TIMEOUT = 120
CONNECT_TIMEOUT = 3
ONLINE_WINDOW = 75
DEFAULT_PEER_PORT = 7600   # the port every start script publishes


def _u(s: str) -> bytes:
    return base64.b64decode(s)


def split_addr(addr: str) -> tuple[str, int]:
    host, _, port = addr.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("address must look like host:port")
    return host.strip("[]"), int(port)


def normalize_addr(addr: str) -> str:
    """Accept what people type when pairing: a bare IP or hostname gets the default peer port."""
    hint = "enter the other computer's IP address, such as 192.168.1.20"
    addr = addr.strip()
    if addr.count(":") > 1 and not addr.startswith("["):     # bare IPv6
        addr = f"[{addr}]"
    if not addr.endswith("]") and ":" in addr:
        try:
            host, port = split_addr(addr)
        except ValueError:
            raise ValueError(hint) from None
    else:
        host, port = addr.strip("[]"), DEFAULT_PEER_PORT
    if not host or not 0 < port < 65536:
        raise ValueError(hint)
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class PairSession:
    def __init__(self, role: str, addr: str):
        self.id = str(uuid.uuid4())
        self.role = role
        self.addr = addr
        self.state = "connecting" if role == "initiator" else "incoming"
        self.sas: str | None = None
        self.peer_card: dict | None = None
        self.peer_fpr: str | None = None
        self.error: str | None = None
        self.demo_warning = False
        self.accepted = asyncio.get_running_loop().create_future()   # responder: user accepts the request
        self.local_ok = asyncio.get_running_loop().create_future()   # user says the codes match

    def view(self) -> dict:
        card = self.peer_card or {}
        return {"id": self.id, "role": self.role, "addr": self.addr, "state": self.state, "sas": self.sas,
                "peer": {"name": card.get("name"), "title": card.get("title"), "dept": card.get("dept"),
                         "fpr": self.peer_fpr, "demo": bool(card.get("demo"))},
                "demo_warning": self.demo_warning, "error": self.error}


class PeerService:
    def __init__(self, node):
        self.node = node
        self.server: asyncio.base_events.Server | None = None
        self.pair_sessions: dict[str, PairSession] = {}
        self._tasks: set[asyncio.Task] = set()

    # --- lifecycle ----------------------------------------------------------

    async def start(self, host: str, port: int) -> int:
        self.server = await asyncio.start_server(self._handle, host, port)
        return self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            self.server = None
        for t in list(self._tasks):
            t.cancel()

    def spawn(self, coro) -> asyncio.Task:
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    # --- helpers --------------------------------------------------------------

    def _anchor(self) -> dict:
        seq, head = self.node.audit.head()
        return {"seq": seq, "hash": head}

    def _lookup(self, fpr: str) -> dict | None:
        return self.node.engine.contact(fpr)

    def _seen(self, fpr: str, addr: str | None = None) -> None:
        values = {"last_seen": db.now()}
        if addr:
            values["addr"] = addr
        db.update(self.node.conn, "contacts", "fpr", fpr, values)

    def online(self, fpr: str) -> bool:
        c = self.node.engine.contact(fpr)
        return bool(c and c["last_seen"] and db.now() - c["last_seen"] < ONLINE_WINDOW)

    def _my_card(self) -> dict:
        p = self.node.profile
        return {"name": p["name"], "title": p.get("title", ""), "dept": p.get("dept", ""),
                "demo": self.node.settings.demo_mode, "addr": self.node.advertise_addr}

    # --- server -----------------------------------------------------------------

    async def _handle(self, reader, writer) -> None:
        source = writer.get_extra_info("peername")
        try:
            hello = await asyncio.wait_for(framing.recv_json(reader), 10)
            if hello.get("t") != "hello" or hello.get("v") != 1:
                raise ChannelError("bad hello")
            if not self.node.service_ready:
                return      # fully locked: offline to peers
            if hello.get("kind") == "pair":
                await self._respond_pair(reader, writer, source)
            elif hello.get("kind") == "session":
                await self._serve_session(reader, writer, hello, source)
        except ChannelError as e:
            if self.node.engine:
                self.node.audit.append("AUTH_FAILURE", {"source": str(source)}, {"error": str(e),
                                                                                   "claimed": hello.get("fpr")})
        except (framing.FrameError, asyncio.TimeoutError, ConnectionError, PairingError) as e:
            log.info("peer connection from %s ended: %s", source, e)
        except Exception:
            log.exception("peer handler crashed")
        finally:
            writer.close()

    async def _serve_session(self, reader, writer, hello, source) -> None:
        if not self.node.service_ready:
            raise ConnectionError("node is fully locked")
        ch = await accept_channel(reader, writer, self.node.identity, hello, self._lookup, self.node.guard,
                                  self._anchor)
        while True:
            try:
                msg_type, body, env = await asyncio.wait_for(ch.recv(), 30)
            except framing.FrameError:
                return
            self._on_envelope(ch.peer_fpr, env)
            if msg_type == "bye":
                return
            try:
                outs = [] if msg_type == "ping" else self.node.engine.handle(msg_type, body, ch.peer_fpr)
                await ch.send("ack", {"ok": True})
            except EngineError as e:
                log.warning("rejected %s from %s: %s", msg_type, ch.peer_fpr, e)
                await ch.send("ack", {"ok": False, "error": str(e)})
                continue
            if outs:
                self.spawn(self.send_outs(outs))
            self.spawn(self.flush_outbox(only=ch.peer_fpr))

    def _on_envelope(self, peer_fpr: str, env: dict) -> None:
        anchor = env.get("anchor") or {}
        if "seq" in anchor:
            self.node.audit.record_anchor(peer_fpr, int(anchor["seq"]), str(anchor["hash"]))
        addr = env["body"].get("_addr") if env.get("type") == "ping" and isinstance(env.get("body"), dict) else None
        try:
            addr = addr if isinstance(addr, str) and len(addr) < 200 and split_addr(addr) else None
        except ValueError:
            addr = None
        self._seen(peer_fpr, addr)

    # --- client -------------------------------------------------------------------

    async def _send(self, peer_fpr: str, msg_type: str, body: dict) -> bool:
        contact = self.node.engine.contact(peer_fpr)
        if not contact:
            return False
        hint = self.node.beacon.hint(peer_fpr) if self.node.beacon else None
        for addr in dict.fromkeys(a for a in (contact["addr"], hint) if a):
            if await self._send_to(addr, contact, msg_type, body):
                if addr != contact["addr"]:      # the handshake proved who answered there
                    db.update(self.node.conn, "contacts", "fpr", peer_fpr, {"addr": addr})
                return True
        return False

    async def _send_to(self, addr: str, contact: dict, msg_type: str, body: dict) -> bool:
        peer_fpr = contact["fpr"]
        try:
            host, port = split_addr(addr)
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), CONNECT_TIMEOUT)
        except (OSError, asyncio.TimeoutError, ValueError):
            return False
        try:
            ch = await asyncio.wait_for(open_channel(reader, writer, self.node.identity, contact,
                                                     self.node.guard, self._anchor), 10)
            await ch.send(msg_type, dict(body, _addr=self.node.advertise_addr) if msg_type == "ping" else body)
            rtype, rbody, env = await asyncio.wait_for(ch.recv(), 15)
            self._on_envelope(peer_fpr, env)
            await ch.send("bye", {})
            if not rbody.get("ok"):
                log.warning("%s rejected %s: %s", peer_fpr, msg_type, rbody.get("error"))
            return True     # delivered; a rejection will not get better by retrying
        except (ChannelError, framing.FrameError, asyncio.TimeoutError, ConnectionError, OSError) as e:
            log.info("send %s to %s failed: %s", msg_type, peer_fpr, e)
            return False
        finally:
            writer.close()

    async def send_outs(self, outs: list[Out]) -> None:
        for out in outs:
            targets = [t for t in out.to if t != self.node.fpr]
            if out.any:
                for t in sorted(targets, key=lambda f: not self.online(f)):
                    if await self._send(t, out.type, out.body):
                        break
                else:
                    for t in targets:
                        self.queue(t, out.type, out.body)
            else:
                for t in targets:
                    if self._has_queued(t) or not await self._send(t, out.type, out.body):
                        self.queue(t, out.type, out.body)
                        self.spawn(self.flush_outbox(only=t))

    def _has_queued(self, peer_fpr: str) -> bool:
        return db.row(self.node.conn, "SELECT id FROM outbox WHERE peer_fpr=? LIMIT 1", (peer_fpr,)) is not None

    def queue(self, peer_fpr: str, msg_type: str, body: dict) -> None:
        oid = db.new_id()
        ct = self.node.vault.enc("service", "outbox", oid, json.dumps(body).encode())
        db.insert(self.node.conn, "outbox", {"id": oid, "peer_fpr": peer_fpr, "msg_type": msg_type,
                                             "body": base64.b64encode(ct).decode(), "created_at": db.now()})

    async def flush_outbox(self, only: str | None = None) -> None:
        sql = "SELECT * FROM outbox" + (" WHERE peer_fpr=?" if only else "") + " ORDER BY created_at"
        skip: set[str] = set()
        for row in db.rows(self.node.conn, sql, (only,) if only else ()):
            if row["peer_fpr"] in skip or not db.row(self.node.conn, "SELECT id FROM outbox WHERE id=?", (row["id"],)):
                continue
            body = json.loads(self.node.vault.dec("service", "outbox", row["id"], _u(row["body"])))
            if await self._send(row["peer_fpr"], row["msg_type"], body):
                self.node.conn.execute("DELETE FROM outbox WHERE id=?", (row["id"],))
            else:
                self.node.conn.execute("UPDATE outbox SET attempts=attempts+1 WHERE id=?", (row["id"],))
                skip.add(row["peer_fpr"])       # keep per-peer order: stop at the first failure

    async def ping_all(self) -> None:
        for c in db.rows(self.node.conn, "SELECT fpr FROM contacts WHERE addr IS NOT NULL"):
            await self._send(c["fpr"], "ping", {})

    # --- pairing ------------------------------------------------------------------

    def begin_pair(self, addr: str) -> PairSession:
        addr = normalize_addr(addr)
        s = PairSession("initiator", addr)
        self.pair_sessions[s.id] = s
        self.spawn(self._initiate_pair(s))
        return s

    def accept_incoming(self, sid: str, ok: bool) -> None:
        s = self.pair_sessions[sid]
        if not s.accepted.done():
            s.accepted.set_result(bool(ok))

    def confirm(self, sid: str, ok: bool, demo_ack: bool = False) -> None:
        s = self.pair_sessions[sid]
        if ok and s.demo_warning and not demo_ack:
            raise ValueError("acknowledge the demo-key warning first")
        if not s.local_ok.done():
            s.local_ok.set_result(bool(ok))

    async def _initiate_pair(self, s: PairSession) -> None:
        writer = None
        try:
            host, port = split_addr(s.addr)
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), CONNECT_TIMEOUT * 2)
            except (OSError, asyncio.TimeoutError):
                raise PairingError(
                    f"Could not reach {s.addr}. Check that both computers are on the same Wi-Fi, that P2PSec is "
                    f"running on the other one, and that it was started with the start script (which opens its "
                    f"firewall for ports 7600 and 7606). Some routers also block devices from seeing each other.") from None
            self.node.audit.append("PAIR_STARTED", {"addr": s.addr}, {"role": "initiator"})
            proto = PairingInitiator(self.node.identity, self._my_card())
            await framing.send_json(writer, {"t": "hello", "v": 1, "kind": "pair"})
            await framing.send_json(writer, proto.msg1())
            s.state = "waiting_for_peer"
            m2 = await asyncio.wait_for(framing.recv_json(reader), PAIR_TIMEOUT)
            if m2.get("t") == "pair_reject":
                raise PairingError("the other person declined the pairing request")
            await framing.send_json(writer, proto.on_msg2(m2))
            proto.on_msg4(await asyncio.wait_for(framing.recv_json(reader), PAIR_TIMEOUT))
            await self._finish_pair(s, proto, reader, writer)
        except Exception as e:
            self._fail(s, e)
        finally:
            if writer:
                writer.close()

    async def _respond_pair(self, reader, writer, source) -> None:
        s = PairSession("responder", f"{source[0]}:{source[1]}" if source else "?")
        self.pair_sessions[s.id] = s
        try:
            proto = PairingResponder(self.node.identity, self._my_card())
            m1 = await asyncio.wait_for(framing.recv_json(reader), 10)
            if not await asyncio.wait_for(s.accepted, PAIR_TIMEOUT):
                await framing.send_json(writer, {"t": "pair_reject"})
                raise PairingError("declined")
            self.node.audit.append("PAIR_STARTED", {"addr": s.addr}, {"role": "responder"})
            await framing.send_json(writer, proto.on_msg1(m1))
            m3 = await asyncio.wait_for(framing.recv_json(reader), PAIR_TIMEOUT)
            await framing.send_json(writer, proto.on_msg3(m3))
            await self._finish_pair(s, proto, reader, writer)
        except Exception as e:
            self._fail(s, e)

    async def _finish_pair(self, s: PairSession, proto, reader, writer) -> None:
        s.sas, s.peer_card, s.peer_fpr = proto.sas, proto.peer_card, proto.peer_identity_fpr
        if s.peer_fpr == self.node.fpr:
            raise PairingError("cannot pair with yourself")
        s.demo_warning = bool(proto.peer_card.get("demo")) and not self.node.settings.demo_mode
        s.state = "compare_codes"
        peer_confirm = self.spawn(asyncio.wait_for(framing.recv_json(reader), PAIR_TIMEOUT))
        # Whoever decides first wins: a "no" (or a hang-up) from the other side ends this session at once.
        await asyncio.wait({s.local_ok, peer_confirm}, timeout=PAIR_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
        remote = None
        if peer_confirm.done() and not s.local_ok.done():
            try:
                remote = proto.on_confirm(peer_confirm.result())
            except (PairingError, framing.FrameError, asyncio.TimeoutError):
                raise PairingError("the other side cancelled the pairing") from None
            if not remote:
                raise PairingError("the other person said the codes do not match")
        local = await asyncio.wait_for(s.local_ok, PAIR_TIMEOUT)
        await framing.send_json(writer, proto.confirm(local))
        if not local:
            raise PairingError("you said the codes do not match")
        s.state = "waiting_for_peer_confirm"
        if remote is None:
            remote = proto.on_confirm(await peer_confirm)
        if not remote:
            raise PairingError("the other person said the codes do not match")
        card = proto.peer_card
        self.node.engine.add_contact({"fpr": s.peer_fpr, "name": card.get("name", "?")[:100],
                                      "title": card.get("title", "")[:100], "dept": card.get("dept", "")[:100],
                                      "ed_pub": proto.peer_ed, "x_pub": proto.peer_x,
                                      "addr": s.addr if s.role == "initiator" else card.get("addr"),
                                      "last_seen": db.now(), "demo": card.get("demo")})
        self.node.audit.append("PAIRED", {"peer_fpr": s.peer_fpr, "peer_name": card.get("name")},
                               {"demo_peer": bool(card.get("demo")), "role": s.role})
        s.state = "paired"
        if s.role == "initiator":
            self.spawn(self._push_groups_to(s.peer_fpr))

    async def _push_groups_to(self, fpr: str) -> None:
        """A newly paired peer may already be listed in groups this node is custodian of."""
        from . import groups
        for head in groups.all_heads(self.node.conn):
            if groups.is_custodian(head, self.node.fpr) and groups.is_member(head, fpr):
                await self.send_outs([Out([fpr], "group_docs", {"group_id": head["group_id"],
                                                                "docs": groups.chain(self.node.conn, head["group_id"])})])

    def _fail(self, s: PairSession, e: Exception) -> None:
        s.state = "failed"
        s.error = str(e) or e.__class__.__name__
        if isinstance(e, asyncio.TimeoutError):
            s.error = "timed out"
        if self.node.engine and s.sas:
            self.node.audit.append("PAIR_REJECTED", {"addr": s.addr, "peer_fpr": s.peer_fpr}, {"reason": s.error})
        log.info("pairing %s failed: %s", s.id, s.error)
