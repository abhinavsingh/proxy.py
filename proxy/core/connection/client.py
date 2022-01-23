# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import ssl
from typing import Optional

from .types import tcpConnectionTypes
from .connection import TcpConnection, TcpConnectionUninitializedException
from ...common.types import HostPort, TcpOrTlsSocket


class TcpClientConnection(TcpConnection):
    """A buffered client connection object."""

    def __init__(
        self,
        conn: TcpOrTlsSocket,
        # optional for unix socket servers
        addr: Optional[HostPort] = None,
    ) -> None:
        super().__init__(tcpConnectionTypes.CLIENT)
        self._conn: Optional[TcpOrTlsSocket] = conn
        self.addr: Optional[HostPort] = addr

    @property
    def address(self) -> str:
        return 'unix:client' if not self.addr else '{0}:{1}'.format(self.addr[0], self.addr[1])

    @property
    def connection(self) -> TcpOrTlsSocket:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn

    def wrap(self, keyfile: str, certfile: str) -> None:
        self.connection.setblocking(True)
        self.flush()
        self._conn = ssl.wrap_socket(
            self.connection,
            server_side=True,
            certfile=certfile,
            keyfile=keyfile,
            ssl_version=ssl.PROTOCOL_TLS,
        )
        self.connection.setblocking(False)
