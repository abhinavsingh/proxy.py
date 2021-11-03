# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from abc import abstractmethod
import socket
import selectors
from typing import Any, Optional, Dict

from ...http.parser import HttpParser, httpParserTypes
from ...common.types import Readables, Writables
from ...common.utils import text_

from ..connection import TcpServerConnection
from .tcp_server import BaseTcpServerHandler


class BaseTcpTunnelHandler(BaseTcpServerHandler):
    """Base TCP tunnel interface."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.request = HttpParser(httpParserTypes.REQUEST_PARSER)
        self.upstream: Optional[TcpServerConnection] = None

    @abstractmethod
    def handle_data(self, data: memoryview) -> Optional[bool]:
        pass    # pragma: no cover

    def initialize(self) -> None:
        self.client.connection.setblocking(False)

    def shutdown(self) -> None:
        if self.upstream:
            print(
                'Connection closed with upstream {0}:{1}'.format(
                    text_(self.request.host), self.request.port,
                ),
            )
            self.upstream.close()
        super().shutdown()

    def get_events(self) -> Dict[socket.socket, int]:
        # Get default client events
        ev: Dict[socket.socket, int] = super().get_events()
        # Read from server if we are connected
        if self.upstream and self.upstream._conn is not None:
            ev[self.upstream.connection] = selectors.EVENT_READ
        # If there is pending buffer for server
        # also register for EVENT_WRITE events
        if self.upstream and self.upstream.has_buffer():
            if self.upstream.connection in ev:
                ev[self.upstream.connection] |= selectors.EVENT_WRITE
            else:
                ev[self.upstream.connection] = selectors.EVENT_WRITE
        return ev

    def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        # Handle client events
        do_shutdown: bool = super().handle_events(readables, writables)
        if do_shutdown:
            return do_shutdown
        # Handle server events
        if self.upstream and self.upstream.connection in readables:
            data = self.upstream.recv()
            if data is None:
                # Server closed connection
                print('Connection closed by server')
                return True
            # tunnel data to client
            self.client.queue(data)
        if self.upstream and self.upstream.connection in writables:
            self.upstream.flush()
        return False

    def connect_upstream(self) -> None:
        assert self.request.host and self.request.port
        self.upstream = TcpServerConnection(
            text_(self.request.host), self.request.port,
        )
        self.upstream.connect()
        print(
            'Connection established with upstream {0}:{1}'.format(
                text_(self.request.host), self.request.port,
            ),
        )
