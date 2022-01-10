# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       tcp
"""
import logging
import selectors
from abc import abstractmethod
from typing import Any, Optional

from ...common.types import Readables, Writables, SelectableEvents
from ...core.acceptor import Work
from ...core.connection import TcpClientConnection


logger = logging.getLogger(__name__)


class BaseTcpServerHandler(Work[TcpClientConnection]):
    """BaseTcpServerHandler implements Work interface.

    BaseTcpServerHandler lifecycle is controlled by Threadless core
    using asyncio.  If you want to also support threaded mode, also
    implement the optional run() method from Work class.

    An instance of BaseTcpServerHandler is created for each client
    connection.  BaseTcpServerHandler ensures that server is always
    ready to accept new data from the client.  It also ensures, client
    is ready to accept new data before flushing data to it.

    Most importantly, BaseTcpServerHandler ensures that pending buffers
    to the client are flushed before connection is closed.

    Implementations must provide::

       a. handle_data(data: memoryview) implementation
       b. Optionally, also implement other Work method
          e.g. initialize, is_inactive, shutdown
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.must_flush_before_shutdown = False
        logger.debug(
            'Work#%d accepted from %s',
            self.work.connection.fileno(),
            self.work.address,
        )

    @abstractmethod
    def handle_data(self, data: memoryview) -> Optional[bool]:
        """Optionally return True to close client connection."""
        pass    # pragma: no cover

    async def get_events(self) -> SelectableEvents:
        events = {}
        # We always want to read from client
        # Register for EVENT_READ events
        if self.must_flush_before_shutdown is False:
            events[self.work.connection.fileno()] = selectors.EVENT_READ
        # If there is pending buffer for client
        # also register for EVENT_WRITE events
        if self.work.has_buffer():
            if self.work.connection.fileno() in events:
                events[self.work.connection.fileno()] |= selectors.EVENT_WRITE
            else:
                events[self.work.connection.fileno()] = selectors.EVENT_WRITE
        return events

    async def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Return True to shutdown work."""
        teardown = await self.handle_writables(
            writables,
        ) or await self.handle_readables(readables)
        if teardown:
            logger.debug(
                'Shutting down client {0} connection'.format(
                    self.work.address,
                ),
            )
        return teardown

    async def handle_writables(self, writables: Writables) -> bool:
        teardown = False
        if self.work.connection.fileno() in writables and self.work.has_buffer():
            logger.debug(
                'Flushing buffer to client {0}'.format(self.work.address),
            )
            self.work.flush()
            if self.must_flush_before_shutdown is True and \
                    not self.work.has_buffer():
                teardown = True
                self.must_flush_before_shutdown = False
        return teardown

    async def handle_readables(self, readables: Readables) -> bool:
        teardown = False
        if self.work.connection.fileno() in readables:
            data = self.work.recv(self.flags.client_recvbuf_size)
            if data is None:
                logger.debug(
                    'Connection closed by client {0}'.format(
                        self.work.address,
                    ),
                )
                teardown = True
            else:
                r = self.handle_data(data)
                if isinstance(r, bool) and r is True:
                    logger.debug(
                        'Implementation signaled shutdown for client {0}'.format(
                            self.work.address,
                        ),
                    )
                    if self.work.has_buffer():
                        logger.debug(
                            'Client {0} has pending buffer, will be flushed before shutting down'.format(
                                self.work.address,
                            ),
                        )
                        self.must_flush_before_shutdown = True
                    else:
                        teardown = True
        return teardown
