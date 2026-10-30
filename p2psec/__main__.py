"""python -m p2psec : run one node (peer service + local UI) in a single event loop."""
import asyncio
import logging

import uvicorn

from .api import Root, create_app
from .config import Settings
from .demo import DemoTeam
from .node import Node


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    settings = Settings.from_env()
    node = Node(settings)
    await node.boot()
    demo = DemoTeam(settings)
    if demo.enabled_on_disk:            # demo mode was on before a restart
        await demo.start()
    logging.getLogger("p2psec").info("node %s fpr=%s peer=%s ui=http://%s:%s", settings.node_id, node.fpr or "(setup)",
                                     node.advertise_addr, settings.ui_host, settings.ui_port)
    server = uvicorn.Server(uvicorn.Config(Root(create_app(node, demo=demo), demo), host=settings.ui_host,
                                           port=settings.ui_port,
                                           log_level="warning", proxy_headers=False, server_header=False))
    try:
        await server.serve()
    finally:
        await demo.stop()
        await node.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
