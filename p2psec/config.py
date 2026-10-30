"""Settings from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class Settings:
    node_id: str = "node"
    data_dir: str = "./data"
    ui_host: str = "127.0.0.1"
    ui_port: int = 8000
    peer_host: str = "0.0.0.0"
    peer_port: int = 7600
    advertise_addr: str = ""
    beacon_port: int = 7601
    beacon: bool = True
    demo_mode: bool = False          # only the in-process demo team's nodes set this
    demo_seed: str = ""
    default_login: bool = True       # a fresh node signs in as user / user until changed
    tom_advertise: str = ""          # LAN address other devices use to reach the demo Tom
    allowed_hosts: tuple[str, ...] = ("127.0.0.1", "localhost")
    idle_lock_seconds: int = 600

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ.get
        s = cls(
            node_id=env("NODE_ID", "node"),
            data_dir=env("DATA_DIR", "./data"),
            ui_host=env("UI_HOST", "127.0.0.1"),
            ui_port=int(env("UI_PORT", "8000")),
            peer_port=int(env("PEER_PORT", "7600")),
            advertise_addr=env("ADVERTISE_ADDR", ""),
            beacon=env("BEACON", "1") == "1",
            default_login=env("DEFAULT_LOGIN", "1") == "1",
            tom_advertise=env("TOM_ADVERTISE", ""),
            allowed_hosts=tuple(h.strip() for h in env("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h.strip()),
            idle_lock_seconds=int(env("IDLE_LOCK_SECONDS", "600")),
        )
        return s
