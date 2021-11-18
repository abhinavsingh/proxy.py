# -*- coding: utf-8 -*-
#
# proxy.py
# ~~~~~~~~
# ⚡ Fast • 🪶 Lightweight • 0️⃣ Dependency • 🔌 Pluggable •
# 😈 TLS interception • 🔒 DNS-over-HTTPS • 🔥 Poor Man's VPN •
# ⏪ Reverse & ⏩ Forward • 👮🏿 "Proxy Server" framework •
# 🌐 "Web Server" framework • ➵ ➶ ➷ ➠ "PubSub" framework •
# 👷 "Work" acceptor & executor framework.
#
# :copyright: (c) 2013-present by Abhinav Singh and contributors.
# :license: BSD, see LICENSE for more details.
#
import ssl
import socket

from typing import Union, Tuple, Optional

from .connection import TcpConnection, TcpConnectionUninitializedException
from .types import tcpConnectionTypes


class TcpClientConnection(TcpConnection):
    """A buffered client connection object."""

    def __init__(
        self,
        conn: Union[ssl.SSLSocket, socket.socket],
        # optional for unix socket servers
        addr: Optional[Tuple[str, int]] = None,
    ) -> None:
        super().__init__(tcpConnectionTypes.CLIENT)
        self._conn: Optional[Union[ssl.SSLSocket, socket.socket]] = conn
        self.addr: Optional[Tuple[str, int]] = addr

    @property
    def address(self) -> str:
        return 'unix:client' if not self.addr else '{0}:{1}'.format(self.addr[0], self.addr[1])

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn

    def wrap(self, keyfile: str, certfile: str) -> None:
        self.connection.setblocking(True)
        self.flush()
        self._conn = ssl.wrap_socket(
            self.connection,
            server_side=True,
            # ca_certs=self.flags.ca_cert_file,
            certfile=certfile,
            keyfile=keyfile,
            ssl_version=ssl.PROTOCOL_TLS,
        )
        self.connection.setblocking(False)
