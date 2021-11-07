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
from typing import Optional

from proxy.proxy import Proxy
from proxy.core.acceptor import AcceptorPool
from proxy.core.base import BaseTcpServerHandler


class EchoServerHandler(BaseTcpServerHandler):
    """Sets client socket to non-blocking during initialization."""

    def initialize(self) -> None:
        self.work.connection.setblocking(False)

    def handle_data(self, data: memoryview) -> Optional[bool]:
        # echo back to client
        self.work.queue(data)
        return None


def main() -> None:
    # This example requires `threadless=True`
    with AcceptorPool(
        flags=Proxy.initialize(port=12345, num_workers=1, threadless=True),
        work_klass=EchoServerHandler,
    ):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
