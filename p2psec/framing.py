"""Length-prefixed frames: 4-byte big-endian length, max 1 MiB."""
from __future__ import annotations

import asyncio
import json

MAX_FRAME = 1 << 20


class FrameError(Exception):
    pass


async def send_frame(writer: asyncio.StreamWriter, data: bytes) -> None:
    if len(data) > MAX_FRAME:
        raise FrameError("frame too large")
    writer.write(len(data).to_bytes(4, "big") + data)
    await writer.drain()


async def recv_frame(reader: asyncio.StreamReader) -> bytes:
    try:
        n = int.from_bytes(await reader.readexactly(4), "big")
        if n > MAX_FRAME:
            raise FrameError("frame too large")
        return await reader.readexactly(n)
    except asyncio.IncompleteReadError as e:
        raise FrameError("connection closed") from e


async def send_json(writer: asyncio.StreamWriter, obj: dict) -> None:
    await send_frame(writer, json.dumps(obj).encode())


async def recv_json(reader: asyncio.StreamReader) -> dict:
    try:
        obj = json.loads(await recv_frame(reader))
    except ValueError as e:
        raise FrameError("bad json") from e
    if not isinstance(obj, dict):
        raise FrameError("bad message")
    return obj
