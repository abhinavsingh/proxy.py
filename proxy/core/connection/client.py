# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import socket
import ssl
from typing import Union, Tuple, Optional

from .connection import TcpConnection, tcpConnectionTypes, TcpConnectionUninitializedException


class TcpClientConnection(TcpConnection):
    """An accepted client connection request."""

    def __init__(self,
                 conn: Union[ssl.SSLSocket, socket.socket],
                 addr: Tuple[str, int]):
        super().__init__(tcpConnectionTypes.CLIENT)
        self._conn: Optional[Union[ssl.SSLSocket, socket.socket]] = conn
        self.addr: Tuple[str, int] = addr

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        if self._conn is None:
            raise TcpConnectionUninitializedException()
        return self._conn
