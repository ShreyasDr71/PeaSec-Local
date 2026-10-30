"""UDP broadcast beacon. Beacons are untrusted hints: they fill the "nearby" list and
refresh a known contact's address. Authenticity always comes from the Noise handshake."""
from __future__ import annotations

import asyncio
import json
import logging
import socket
import time


log = logging.getLogger("p2psec.discovery")
INTERVAL = 15
NEARBY_TTL = 60


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, beacon: "Beacon"):
        self.beacon = beacon

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            msg = json.loads(data[:2048])
            fpr, name, peer_addr = str(msg["fpr"]), str(msg["name"])[:100], str(msg["addr"])[:200]
        except (ValueError, KeyError, TypeError):
            return
        self.beacon.on_beacon(fpr, name, peer_addr, bool(msg.get("demo")))


class Beacon:
    def __init__(self, node):
        self.node = node
        self.nearby: dict[str, dict] = {}
        self.transport = None
        self.task = None

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("", self.node.settings.beacon_port))
        except OSError as e:
            log.warning("beacon disabled: %s", e)
            sock.close()
            return
        self.transport, _ = await loop.create_datagram_endpoint(lambda: _Proto(self), sock=sock)
        self.task = loop.create_task(self._announce())

    def stop(self) -> None:
        if self.task:
            self.task.cancel()
        if self.transport:
            self.transport.close()

    async def _announce(self) -> None:
        while True:
            if self.node.fpr:
                msg = json.dumps({"fpr": self.node.fpr, "name": self.node.profile.get("name", ""),
                                  "addr": self.node.advertise_addr, "demo": self.node.settings.demo_mode}).encode()
                try:
                    self.transport.sendto(msg, ("255.255.255.255", self.node.settings.beacon_port))
                except OSError as e:
                    log.debug("beacon send failed: %s", e)
            await asyncio.sleep(INTERVAL)

    def on_beacon(self, fpr: str, name: str, addr: str, demo: bool) -> None:
        if fpr == self.node.fpr:
            return
        # Never overwrite a paired contact's address from an unauthenticated beacon; the peer layer
        # only tries this address as a fallback when the stored one fails.
        self.nearby[fpr] = {"fpr": fpr, "name": name, "addr": addr, "demo": demo, "seen": time.time()}

    def hint(self, fpr: str) -> str | None:
        n = self.nearby.get(fpr)
        return n["addr"] if n and n["seen"] > time.time() - NEARBY_TTL else None

    def list(self) -> list[dict]:
        cutoff = time.time() - NEARBY_TTL
        return [dict(v, paired=bool(self.node.engine and self.node.engine.contact(k)))
                for k, v in self.nearby.items() if v["seen"] > cutoff]
