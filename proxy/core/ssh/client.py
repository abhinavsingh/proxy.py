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
from typing import Union

from ..connection import TcpClientConnection


class SshClient(TcpClientConnection):
    """Overrides TcpClientConnection.

    This is necessary because paramiko ``fileno()`` can be used for polling
    but not for send / recv.
    """

    @property
    def connection(self) -> Union[ssl.SSLSocket, socket.socket]:
        # Dummy return to comply with
        return socket.socket()
