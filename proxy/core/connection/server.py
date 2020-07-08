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

from .connection import TcpConnection, tcpConnectionTypes, TcpConnectionUninitializedException
from ...common.utils import new_socket_connection


class TcpServerConnection(TcpConnection):
    """Establishes connection to upstream server."""

    def __init__(self, host: str, port: int):
        super().__init__(tcpConnectionTypes.SERVER)
        self._conn: Optional[Union[ssl.SSLSocket, socket.socket]] = None
        self.addr: Tuple[str, int] = (host, int(port))

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn

    def connect(self) -> None:
        if self._conn is not None:
            return
        self._conn = new_socket_connection(self.addr)

    def wrap(self, hostname: str, ca_file: Optional[str]) -> None:
        ctx = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=ca_file)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1
        ctx.check_hostname = True
        self.connection.setblocking(True)
        self._conn = ctx.wrap_socket(
            self.connection,
            server_hostname=hostname)
        self.connection.setblocking(False)
