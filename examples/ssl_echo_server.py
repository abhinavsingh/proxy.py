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
from proxy.common.utils import wrap_socket
from proxy.core.acceptor import AcceptorPool
from proxy.core.connection import TcpClientConnection

from proxy.core.base import BaseTcpServerHandler


class EchoSSLServerHandler(BaseTcpServerHandler):
    """Wraps client socket during initialization."""

    def initialize(self) -> None:
        # Acceptors don't perform TLS handshake.  Perform the same
        # here using wrap_socket() utility.
        assert self.flags.keyfile is not None and self.flags.certfile is not None
        conn = wrap_socket(
            self.client.connection,
            self.flags.keyfile,
            self.flags.certfile,
        )
        conn.setblocking(False)
        # Upgrade plain TcpClientConnection to SSL connection object
        self.client = TcpClientConnection(
            conn=conn, addr=self.client.addr,
        )

    def handle_data(self, data: memoryview) -> Optional[bool]:
        # echo back to client
        self.client.queue(data)
        return None


def main() -> None:
    # This example requires `threadless=True`
    with AcceptorPool(
        flags=Proxy.initialize(
            port=12345,
            num_workers=1,
            threadless=True,
            keyfile='https-key.pem',
            certfile='https-signed-cert.pem',
        ),
        work_klass=EchoSSLServerHandler,
    ):
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
