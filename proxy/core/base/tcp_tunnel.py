# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
import selectors

from abc import abstractmethod
from typing import Any, Optional

from ...http.parser import HttpParser, httpParserTypes
from ...common.types import Readables, SelectableEvents, Writables
from ...common.utils import text_

from ..connection import TcpServerConnection
from .tcp_server import BaseTcpServerHandler

logger = logging.getLogger(__name__)


class BaseTcpTunnelHandler(BaseTcpServerHandler):
    """BaseTcpTunnelHandler build on-top of BaseTcpServerHandler work class.

    On-top of BaseTcpServerHandler implementation,
    BaseTcpTunnelHandler introduces an upstream TcpServerConnection
    and adds it to the core event loop when needed.

    Currently, implementations must call connect_upstream from within
    handle_data.  See HttpsConnectTunnelHandler for example usage.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.request = HttpParser(
            httpParserTypes.REQUEST_PARSER,
            enable_proxy_protocol=self.flags.enable_proxy_protocol,
        )
        self.upstream: Optional[TcpServerConnection] = None

    @abstractmethod
    def handle_data(self, data: memoryview) -> Optional[bool]:
        pass    # pragma: no cover

    def initialize(self) -> None:
        self.work.connection.setblocking(False)

    def shutdown(self) -> None:
        if self.upstream:
            logger.debug(
                'Connection closed with upstream {0}:{1}'.format(
                    text_(self.request.host), self.request.port,
                ),
            )
            self.upstream.close()
        super().shutdown()

    async def get_events(self) -> SelectableEvents:
        # Get default client events
        ev: SelectableEvents = await super().get_events()
        # Read from server if we are connected
        if self.upstream and self.upstream._conn is not None:
            ev[self.upstream.connection.fileno()] = selectors.EVENT_READ
        # If there is pending buffer for server
        # also register for EVENT_WRITE events
        if self.upstream and self.upstream.has_buffer():
            if self.upstream.connection.fileno() in ev:
                ev[self.upstream.connection.fileno()] |= selectors.EVENT_WRITE
            else:
                ev[self.upstream.connection.fileno()] = selectors.EVENT_WRITE
        return ev

    async def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        # Handle client events
        do_shutdown: bool = await super().handle_events(readables, writables)
        if do_shutdown:
            return do_shutdown
        # Handle server events
        if self.upstream and self.upstream.connection.fileno() in readables:
            data = self.upstream.recv()
            if data is None:
                # Server closed connection
                logger.debug('Connection closed by server')
                return True
            # tunnel data to client
            self.work.queue(data)
        if self.upstream and self.upstream.connection.fileno() in writables:
            self.upstream.flush()
        return False

    def connect_upstream(self) -> None:
        assert self.request.host and self.request.port
        self.upstream = TcpServerConnection(
            text_(self.request.host), self.request.port,
        )
        self.upstream.connect()
        logger.debug(
            'Connection established with upstream {0}:{1}'.format(
                text_(self.request.host), self.request.port,
            ),
        )
