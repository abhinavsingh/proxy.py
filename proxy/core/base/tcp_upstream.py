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
import logging

from typing import Tuple, List, Optional

from ...common.types import Readables, Writables
from ...core.connection import TcpServerConnection

logger = logging.getLogger(__name__)


class TcpUpstreamConnectionHandler:
    """TcpUpstreamConnectionHandler can be used to insert an upstream server
    connection lifecycle within asynchronous proxy.py lifecycle.

    TcpUpstreamConnectionHandler can be used as a mixin or as standalone instances,
    e.g. when your class wants to maintain multiple upstream connections,
    don't use in mixin mode.  Within mixin mode, your class will get a
    `self.upstream` object for use.

    Call `initialize_upstream` to initialize the upstream connection object.
    Then, directly use `self.upstream` object within your class.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.upstream: Optional[TcpServerConnection] = None
        self.total_size = 0

    def initialize_upstream(self, addr: str, port: int) -> None:
        self.upstream = TcpServerConnection(addr, port)

    def get_descriptors(self) -> Tuple[List[socket.socket], List[socket.socket]]:
        if not self.upstream:
            return [], []
        return [self.upstream.connection], [self.upstream.connection] if self.upstream.has_buffer() else []

    def read_from_descriptors(self, r: Readables) -> bool:
        if self.upstream and self.upstream.connection in r:
            try:
                raw = self.upstream.recv(self.flags.server_recvbuf_size)
                if raw is not None:
                    self.total_size += len(raw)
                    self.client.queue(raw)
                else:
                    return True     # Teardown because upstream proxy closed the connection
            except ssl.SSLWantReadError:
                logger.info('Upstream SSLWantReadError, will retry')
                return False
            except ConnectionResetError:
                logger.debug('Connection reset by upstream')
                return True
        return False

    def write_to_descriptors(self, w: Writables) -> bool:
        if self.upstream and self.upstream.connection in w and self.upstream.has_buffer():
            try:
                self.upstream.flush()
            except ssl.SSLWantWriteError:
                logger.info('Upstream SSLWantWriteError, will retry')
                return False
            except BrokenPipeError:
                logger.debug('BrokenPipeError when flushing to upstream')
                return True
        return False
