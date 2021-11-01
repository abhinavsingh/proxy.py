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
from paramiko.channel import Channel

from ...common.constants import DEFAULT_BUFFER_SIZE

from ..connection import TcpClientConnection


class TunnelClientConnection(TcpClientConnection):
    """Overrides TcpClientConnection.

    This is necessary because paramiko fileno() can be used for polling
    but not for send / recv, for which channel must be used
    """

    def __init__(self, chan: Channel):
        self.chan = chan
        # A FileDescriptorLike object is required
        # for selectorKey to work.  Hence we are forced
        # to call chan.fileno here.  This internally creates
        # a pipe and will result in double open file.
        conn = socket.fromfd(
            self.chan.fileno(),
            family=socket.AF_INET,
            type=socket.SOCK_STREAM)
        super().__init__(conn, (self.chan.getpeername(), 22))

    # We overwrite these methods from [TcpConnection] class
    # because we cannot defeat type checker here without changing
    # the entire type system for connection classes.  Problem is
    # that connection classes expects a socket object, but
    # paramiko has none, it got a channel, and we cannot hardcode
    # dependency upon channel (as paramiko is optional).

    def send(self, data: bytes) -> int:
        """Users must handle BrokenPipeError exceptions"""
        return self.chan.send(data)

    def _recv(self, buffer_size: int = DEFAULT_BUFFER_SIZE) -> bytes:
        return self.chan.recv(buffer_size)

    def _close(self) -> None:
        self.chan.close()
