# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time

from proxy.core.acceptor import AcceptorPool
from proxy.proxy import Proxy

from examples.base_server import BaseServerHandler


class EchoServerHandler(BaseServerHandler):  # type: ignore
    """Sets client socket to non-blocking during initialization."""

    def initialize(self) -> None:
        self.client.connection.setblocking(False)

    def handle_data(self, data: memoryview) -> None:
        # echo back to client
        self.client.queue(data)


def main() -> None:
    # This example requires `threadless=True`
    pool = AcceptorPool(
        flags=Proxy.initialize(port=12345, num_workers=1, threadless=True),
        work_klass=EchoServerHandler)
    try:
        pool.setup()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        pool.shutdown()


if __name__ == '__main__':
    main()
