import asyncio
import time
import pytest
from p2psec.crypto import Identity
from p2psec.channel import open_channel, accept_channel, ReplayGuard, ChannelError
from p2psec import framing


async def _pair_streams(server_identity, lookup, guard, handler_result):
    async def handle(reader, writer):
        try:
            hello = await framing.recv_json(reader)
            ch = await accept_channel(reader, writer, server_identity, hello, lookup, guard)
            handler_result.append(await ch.recv())
            await ch.send("pong", {"ok": True})
        except Exception as e:
            handler_result.append(e)
        finally:
            writer.close()
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_round_trip_between_pinned_identities(conn):
    a, b = Identity.generate(), Identity.generate()
    got = []
    lookup = lambda fpr: {"x_pub": a.x_pub_bytes()} if fpr == a.fingerprint() else None
    server, port = await _pair_streams(b, lookup, ReplayGuard(conn), got)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    ch = await open_channel(reader, writer, a, {"ed_pub": b.ed_pub_bytes(), "x_pub": b.x_pub_bytes()}, ReplayGuard(conn))
    big = "x" * 200_000   # larger than one Noise message
    await ch.send("ping", {"data": big})
    t, body, _ = await ch.recv()
    assert t == "pong" and body == {"ok": True}
    assert got[0][0] == "ping" and got[0][1]["data"] == big
    assert ch.peer_fpr == b.fingerprint()
    server.close()


async def test_unpinned_initiator_rejected(conn):
    a, b = Identity.generate(), Identity.generate()
    got = []
    server, port = await _pair_streams(b, lambda fpr: None, ReplayGuard(conn), got)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises((ChannelError, framing.FrameError)):
        ch = await open_channel(reader, writer, a, {"ed_pub": b.ed_pub_bytes(), "x_pub": b.x_pub_bytes()}, ReplayGuard(conn))
        await ch.recv()
    await asyncio.sleep(0.05)
    assert isinstance(got[0], ChannelError)
    server.close()


async def test_wrong_pinned_responder_key_fails(conn):
    a, b, impostor = Identity.generate(), Identity.generate(), Identity.generate()
    got = []
    lookup = lambda fpr: {"x_pub": a.x_pub_bytes()}
    server, port = await _pair_streams(impostor, lookup, ReplayGuard(conn), got)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises((ChannelError, framing.FrameError)):
        ch = await open_channel(reader, writer, a, {"ed_pub": b.ed_pub_bytes(), "x_pub": b.x_pub_bytes()}, ReplayGuard(conn))
        await ch.send("ping", {})
        await ch.recv()
    server.close()


async def test_tampered_frame_rejected(conn):
    a, b = Identity.generate(), Identity.generate()
    got = []
    lookup = lambda fpr: {"x_pub": a.x_pub_bytes()}
    server, port = await _pair_streams(b, lookup, ReplayGuard(conn), got)
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    ch = await open_channel(reader, writer, a, {"ed_pub": b.ed_pub_bytes(), "x_pub": b.x_pub_bytes()}, ReplayGuard(conn))
    ct = bytearray(ch.noise.encrypt(b"\x00" + b'{"bad":1}'))
    ct[3] ^= 0xFF
    await framing.send_frame(writer, bytes(ct))
    await asyncio.sleep(0.1)
    assert isinstance(got[0], ChannelError)
    server.close()


def test_replay_guard(conn):
    g = ReplayGuard(conn)
    now = time.time()
    g.check("m1", now)
    with pytest.raises(ChannelError, match="replay"):
        g.check("m1", now)
    with pytest.raises(ChannelError, match="skew"):
        g.check("m2", now - 301)
