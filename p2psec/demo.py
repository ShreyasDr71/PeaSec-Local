"""Opt-in demo team: six seeded nodes running inside this same process.

Nothing here runs unless someone presses "Demo mode". Each demo node has its own data
directory, vault, keys and peer port, exactly like a real node; they talk to each other
over loopback TCP. Tom's peer port is the one published to the LAN so another device can
pair with him. Demo keys derive from a public seed: never store real secrets in them.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
from dataclasses import replace

from . import seed
from .config import Settings
from .node import DEMO_PASSWORD, Node

log = logging.getLogger("p2psec.demo")
DEMO_SEED = "p2psec-demo-seed-2026"     # public on purpose
TEAM_IDS = list(seed.TEAM)
PORT_OFFSET = {n: i + 1 for i, n in enumerate(TEAM_IDS)}     # priya 7601 ... tom 7606


class DemoTeam:
    def __init__(self, main: Settings, params: dict | None = None, port_base: int = 7600):
        self.main = main
        self.params = params
        self.port_base = port_base          # 0 = random ports (tests)
        self.root = os.path.join(main.data_dir, "demo")
        self.marker = os.path.join(self.root, "enabled")
        self.nodes: dict[str, Node] = {}
        self.apps: dict = {}
        self._lock = asyncio.Lock()

    @property
    def running(self) -> bool:
        return bool(self.nodes)

    @property
    def enabled_on_disk(self) -> bool:
        return os.path.exists(self.marker)

    def _settings(self, nid: str) -> Settings:
        port = self.port_base + PORT_OFFSET[nid] if self.port_base else 0
        advertise = ""
        if nid == "tom" and self.main.tom_advertise:
            advertise = self.main.tom_advertise
        return replace(self.main, node_id=nid, data_dir=os.path.join(self.root, nid), demo_mode=True,
                       demo_seed=DEMO_SEED, peer_host="0.0.0.0" if nid == "tom" else "127.0.0.1",
                       peer_port=port, advertise_addr=advertise, beacon=False, default_login=False)

    async def start(self) -> None:
        async with self._lock:
            if self.running:
                return
            os.makedirs(self.root, exist_ok=True)
            nodes = {nid: Node(self._settings(nid)) for nid in TEAM_IDS}
            for n in nodes.values():
                await n.start_peer()
            # teammates reach each other over loopback; Tom may advertise a LAN address to other devices
            internal = {nid: f"127.0.0.1:{n.listen_port}" for nid, n in nodes.items()}
            for nid, n in nodes.items():
                n.advertise_addr = n.settings.advertise_addr or internal[nid]
                if not n.initialized:
                    seed.build(n, params=self.params, addr_of=internal.get)
                    n.full_lock()
                await n.unlock(DEMO_PASSWORD)
                n.soft_lock()
            self.nodes = nodes
            open(self.marker, "w").close()
            from .api import create_app
            self.apps = {nid: create_app(n, base=f"/demo/{nid}") for nid, n in nodes.items()}
            log.info("demo team started")

    async def stop(self, forget: bool = False) -> None:
        async with self._lock:
            for n in self.nodes.values():
                await n.shutdown(close_db=True)
            self.nodes, self.apps = {}, {}
            if forget and os.path.exists(self.marker):
                os.remove(self.marker)

    async def reset(self) -> None:
        await self.stop()
        await asyncio.sleep(0.1)       # let Windows release the database files
        shutil.rmtree(self.root, ignore_errors=True)
        await self.start()

    def users(self) -> list[dict]:
        return [{"id": nid, "name": seed.TEAM[nid]["name"], "title": seed.TEAM[nid]["title"],
                 "url": f"/demo/{nid}/", "login": nid} for nid in TEAM_IDS]
