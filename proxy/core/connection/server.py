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
import socket

from typing import Optional, Union, Tuple

from ...common.utils import new_socket_connection

from .connection import TcpConnection, TcpConnectionUninitializedException
from .types import tcpConnectionTypes


class TcpServerConnection(TcpConnection):
    """A buffered server connection object."""

    def __init__(self, host: str, port: int) -> None:
        super().__init__(tcpConnectionTypes.SERVER)
        self._conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None
        self.addr: Tuple[str, int] = (host, port)
        self.closed = True

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn

    def connect(
            self,
            addr: Optional[Tuple[str, int]] = None,
            source_address: Optional[Tuple[str, int]] = None,
    ) -> None:
        assert self._conn is None
        self._conn = new_socket_connection(
            addr or self.addr, source_address=source_address,
        )
        self.closed = False

    def wrap(self, hostname: str, ca_file: Optional[str]) -> None:
        ctx = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=ca_file,
        )
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.check_hostname = True
        self.connection.setblocking(True)
        self._conn = ctx.wrap_socket(
            self.connection,
            server_hostname=hostname,
        )
        self.connection.setblocking(False)
