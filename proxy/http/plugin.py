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
import argparse

from abc import ABC, abstractmethod
from typing import List, Union, Optional, TYPE_CHECKING

from ..core.event import EventQueue
from ..core.connection import TcpClientConnection

from .parser import HttpParser
from .descriptors import DescriptorsHandlerMixin
from .mixins import TlsInterceptionPropertyMixin

if TYPE_CHECKING:
    from ..core.connection import UpstreamConnectionPool


class HttpProtocolHandlerPlugin(
        DescriptorsHandlerMixin,
        TlsInterceptionPropertyMixin,
        ABC,
):
    """Base HttpProtocolHandler Plugin class.

    NOTE: This is an internal plugin and in most cases only useful for core contributors.
    If you are looking for proxy server plugins see `<proxy.HttpProxyBasePlugin>`.

    Implements various lifecycle events for an accepted client connection.
    Following events are of interest:

    1. Client Connection Accepted
       A new plugin instance is created per accepted client connection.
       Add your logic within __init__ constructor for any per connection setup.
    2. Client Request Chunk Received
       on_client_data is called for every chunk of data sent by the client.
    3. Client Request Complete
       on_request_complete is called once client request has completed.
    4. Server Response Chunk Received
       on_response_chunk is called for every chunk received from the server.
    5. Client Connection Closed
       Add your logic within `on_client_connection_close` for any per connection tear-down.
    """

    def __init__(
            self,
            uid: str,
            flags: argparse.Namespace,
            client: TcpClientConnection,
            request: HttpParser,
            event_queue: Optional[EventQueue] = None,
            upstream_conn_pool: Optional['UpstreamConnectionPool'] = None,
    ):
        self.uid: str = uid
        self.flags: argparse.Namespace = flags
        self.client: TcpClientConnection = client
        self.request: HttpParser = request
        self.event_queue = event_queue
        self.upstream_conn_pool = upstream_conn_pool
        super().__init__()

    @staticmethod
    @abstractmethod
    def protocols() -> List[int]:
        raise NotImplementedError()

    @abstractmethod
    def on_client_data(self, raw: memoryview) -> Optional[memoryview]:
        """Called only after original request has been completely received."""
        return raw  # pragma: no cover

    @abstractmethod
    def on_request_complete(self) -> Union[socket.socket, bool]:
        """Called right after client request parser has reached COMPLETE state."""
        return False  # pragma: no cover

    @abstractmethod
    def on_response_chunk(self, chunk: List[memoryview]) -> List[memoryview]:
        """Handle data chunks as received from the server.

        Return optionally modified chunk to return back to client."""
        return chunk  # pragma: no cover

    @abstractmethod
    def on_client_connection_close(self) -> None:
        """Client connection shutdown has been received, flush has been called,
        perform any cleanup work here.
        """
        pass  # pragma: no cover
