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
from proxy.common.utils import wrap_socket
from proxy.core.connection import TcpClientConnection


class EchoSSLServerHandler(BaseTcpServerHandler[TcpClientConnection]):
    """Wraps client socket during initialization."""

    @staticmethod
    def create(**kwargs: Any) -> TcpClientConnection:   # pragma: no cover
        return TcpClientConnection(**kwargs)

    def initialize(self) -> None:
        # Acceptors don't perform TLS handshake.  Perform the same
        # here using wrap_socket() utility.
        assert self.flags.keyfile is not None and self.flags.certfile is not None
        conn = wrap_socket(
            self.work.connection,
            self.flags.keyfile,
            self.flags.certfile,
        )
        conn.setblocking(False)
        # Upgrade plain TcpClientConnection to SSL connection object
        self.work = TcpClientConnection(
            conn=conn, addr=self.work.addr,
        )

    def handle_data(self, data: memoryview) -> Optional[bool]:
        # echo back to client
        self.work.queue(data)
        return None


def main() -> None:
    # This example requires `threadless=True`
    with Proxy(
        work_klass=EchoSSLServerHandler,
        threadless=True,
        num_workers=1,
        port=12345,
        keyfile='https-key.pem',
        certfile='https-signed-cert.pem',
    ):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
