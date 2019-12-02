# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from abc import ABC, abstractmethod
from typing import Optional

from ..parser import HttpParser

from ...common.flags import Flags

from ...core.event import EventQueue
from ...core.connection import TcpClientConnection


class HttpProxyBasePlugin(ABC):
    """Base HttpProxyPlugin Plugin class.

    Implement various lifecycle event methods to customize behavior."""

    def __init__(
            self,
            uid: str,
            flags: Flags,
            client: TcpClientConnection,
            event_queue: EventQueue) -> None:
        self.uid = uid                  # pragma: no cover
        self.flags = flags              # pragma: no cover
        self.client = client            # pragma: no cover
        self.event_queue = event_queue  # pragma: no cover

    def name(self) -> str:
        """A unique name for your plugin.

        Defaults to name of the class. This helps plugin developers to directly
        access a specific plugin by its name."""
        return self.__class__.__name__      # pragma: no cover

    @abstractmethod
    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Handler called just before Proxy upstream connection is established.

        Return optionally modified request object.
        Raise HttpRequestRejected or HttpProtocolException directly to drop the connection."""
        return request  # pragma: no cover

    @abstractmethod
    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Handler called before dispatching client request to upstream.

        Note: For pipelined (keep-alive) connections, this handler can be
        called multiple times, for each request sent to upstream.

        Note: If TLS interception is enabled, this handler can
        be called multiple times if client exchanges multiple
        requests over same SSL session.

        Return optionally modified request object to dispatch to upstream.
        Return None to drop the request data, e.g. in case a response has already been queued.
        Raise HttpRequestRejected or HttpProtocolException directly to
            teardown the connection with client.
        """
        return request  # pragma: no cover

    @abstractmethod
    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        """Handler called right after receiving raw response from upstream server.

        For HTTPS connections, chunk will be encrypted unless
        TLS interception is also enabled."""
        return chunk  # pragma: no cover

    @abstractmethod
    def on_upstream_connection_close(self) -> None:
        """Handler called right after upstream connection has been closed."""
        pass  # pragma: no cover
