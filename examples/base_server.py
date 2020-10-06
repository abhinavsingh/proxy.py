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

from typing import Dict, Any

from proxy.core.acceptor import Work
from proxy.common.types import Readables, Writables


class BaseServerHandler(Work):
    """BaseServerHandler implements Work interface.

    An instance of BaseServerHandler is created for each client
    connection.  BaseServerHandler lifecycle is controlled by
    Threadless core using asyncio.

    Implementation must provide:
    a) handle_data(data: memoryview)
    c) (optionally) intialize, is_inactive and shutdown methods
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        print('Connection accepted from {0}'.format(self.client.addr))

    @abstractmethod
    def handle_data(self, data: memoryview) -> None:
        pass    # pragma: no cover

    def get_events(self) -> Dict[socket.socket, int]:
        # We always want to read from client
        # Register for EVENT_READ events
        events = {self.client.connection: selectors.EVENT_READ}
        # If there is pending buffer for client
        # also register for EVENT_WRITE events
        if self.client.has_buffer():
            events[self.client.connection] |= selectors.EVENT_WRITE
        return events

    def handle_events(
            self,
            readables: Readables,
            writables: Writables) -> bool:
        """Return True to shutdown work."""
        if self.client.connection in readables:
            try:
                data = self.client.recv()
                if data is None:
                    # Client closed connection, signal shutdown
                    print(
                        'Connection closed by client {0}'.format(
                            self.client.addr))
                    return True
                self.handle_data(data)
            except ConnectionResetError:
                print(
                    'Connection reset by client {0}'.format(
                        self.client.addr))
                return True

        if self.client.connection in writables:
            self.client.flush()

        return False
