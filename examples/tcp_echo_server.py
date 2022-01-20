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
from typing import Any, Optional

from proxy import Proxy
from proxy.core.base import BaseTcpServerHandler
from proxy.core.connection import TcpClientConnection


class EchoServerHandler(BaseTcpServerHandler[TcpClientConnection]):
    """Sets client socket to non-blocking during initialization."""

    @staticmethod
    def create(**kwargs: Any) -> TcpClientConnection:   # pragma: no cover
        return TcpClientConnection(**kwargs)

    def initialize(self) -> None:
        self.work.connection.setblocking(False)

    def handle_data(self, data: memoryview) -> Optional[bool]:
        # echo back to client
        self.work.queue(data)
        return None


def main() -> None:
    # This example requires `threadless=True`
    with Proxy(
        work_klass=EchoServerHandler,
        threadless=True,
        num_workers=1,
        port=12345,
    ):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
