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
from proxy.core.connection import TcpClientConnection
from proxy.common.flags import Flags
from proxy.common.utils import wrap_socket

from examples.base_echo_server import BaseEchoServerHandler


class EchoSSLServerHandler(BaseEchoServerHandler):  # type: ignore
    """Wraps client socket during initialization."""

    def initialize(self) -> None:
        # Acceptors don't perform TLS handshake.  Perform the same
        # here using wrap_socket() utility.
        assert self.flags.keyfile is not None and self.flags.certfile is not None
        conn = wrap_socket(
            self.client.connection,  # type: ignore
            self.flags.keyfile,
            self.flags.certfile)
        conn.setblocking(False)
        # Upgrade plain TcpClientConnection to SSL connection object
        self.client = TcpClientConnection(
            conn=conn, addr=self.client.addr)  # type: ignore


def main() -> None:
    # This example requires `threadless=True`
    pool = AcceptorPool(
        flags=Flags(
            port=12345,
            num_workers=1,
            threadless=True,
            keyfile='https-key.pem',
            certfile='https-signed-cert.pem'),
        work_klass=EchoSSLServerHandler)
    try:
        pool.setup()
        while True:
            time.sleep(1)
    finally:
        pool.shutdown()


if __name__ == '__main__':
    main()
