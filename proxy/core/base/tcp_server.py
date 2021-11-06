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
import logging
import selectors

from abc import abstractmethod
from typing import Dict, Any, Optional

from proxy.core.acceptor import Work
from proxy.common.types import Readables, Writables

logger = logging.getLogger(__name__)


class BaseTcpServerHandler(Work):
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

    Implementations must provide:
    a) handle_data(data: memoryview) implementation
    b) Optionally, also implement other Work method
       e.g. initialize, is_inactive, shutdown
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.must_flush_before_shutdown = False
        logger.debug('Connection accepted from {0}'.format(self.client.addr))

    @abstractmethod
    def handle_data(self, data: memoryview) -> Optional[bool]:
        """Optionally return True to close client connection."""
        pass    # pragma: no cover

    def get_events(self) -> Dict[socket.socket, int]:
        events = {}
        # We always want to read from client
        # Register for EVENT_READ events
        if self.must_flush_before_shutdown is False:
            events[self.client.connection] = selectors.EVENT_READ
        # If there is pending buffer for client
        # also register for EVENT_WRITE events
        if self.client.has_buffer():
            if self.client.connection in events:
                events[self.client.connection] |= selectors.EVENT_WRITE
            else:
                events[self.client.connection] = selectors.EVENT_WRITE
        return events

    def handle_events(
            self,
            readables: Readables,
            writables: Writables,
    ) -> bool:
        """Return True to shutdown work."""
        teardown = self.handle_writables(
            writables,
        ) or self.handle_readables(readables)
        if teardown:
            logger.debug(
                'Shutting down client {0} connection'.format(
                    self.client.addr,
                ),
            )
        return teardown

    def handle_writables(self, writables: Writables) -> bool:
        teardown = False
        if self.client.connection in writables and self.client.has_buffer():
            logger.debug(
                'Flushing buffer to client {0}'.format(self.client.addr),
            )
            self.client.flush()
            if self.must_flush_before_shutdown is True:
                teardown = True
            self.must_flush_before_shutdown = False
        return teardown

    def handle_readables(self, readables: Readables) -> bool:
        teardown = False
        if self.client.connection in readables:
            data = self.client.recv(self.flags.client_recvbuf_size)
            if data is None:
                # Client closed connection, signal shutdown
                logger.debug(
                    'Connection closed by client {0}'.format(
                        self.client.addr,
                    ),
                )
                teardown = True
            else:
                r = self.handle_data(data)
                if isinstance(r, bool) and r is True:
                    logger.debug(
                        'Implementation signaled shutdown for client {0}'.format(
                            self.client.addr,
                        ),
                    )
                    if self.client.has_buffer():
                        logger.debug(
                            'Client {0} has pending buffer, will be flushed before shutting down'.format(
                                self.client.addr,
                            ),
                        )
                        self.must_flush_before_shutdown = True
                    else:
                        teardown = True
            # except ConnectionResetError:
            #     logger.debug(
            #         'Connection reset by client {0}'.format(
            #             self.client.addr,
            #         ),
            #     )
            #     teardown = True
        return teardown
