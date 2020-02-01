# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import random
import socket
from typing import Optional, Any

from ..common.constants import DEFAULT_BUFFER_SIZE, SLASH, COLON
from ..common.utils import new_socket_connection
from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser


class ProxyPoolPlugin(HttpProxyBasePlugin):
    """Proxy incoming client proxy requests through a set of upstream proxies."""

    # Run two separate instances of proxy.py
    # on port 9000 and 9001 BUT WITHOUT ProxyPool plugin
    # to avoid infinite loops.
    UPSTREAM_PROXY_POOL = [
        ('localhost', 9000),
        ('localhost', 9001),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.conn: Optional[socket.socket] = None

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Avoid upstream connection of server in the request.
        Initialize, connection to upstream proxy.
        """
        # Implement your own logic here e.g. round-robin, least connection etc.
        self.conn = new_socket_connection(
            random.choice(self.UPSTREAM_PROXY_POOL))
        return None

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        request.path = self.rebuild_original_path(request)
        self.tunnel(request)
        # Returning None indicates core to gracefully
        # flush client buffer and teardown the connection
        return None

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        """Will never be called since we didn't establish an upstream connection."""
        return chunk

    def on_upstream_connection_close(self) -> None:
        """Will never be called since we didn't establish an upstream connection."""
        pass

    def tunnel(self, request: HttpParser) -> None:
        """Send to upstream proxy, receive from upstream proxy, queue back to client."""
        assert self.conn
        self.conn.send(request.build())
        response = self.conn.recv(DEFAULT_BUFFER_SIZE)
        self.client.queue(memoryview(response))

    @staticmethod
    def rebuild_original_path(request: HttpParser) -> bytes:
        """Re-builds original upstream server URL.

        proxy server core by default strips upstream host:port
        from incoming client proxy request.
        """
        assert request.url and request.host and request.port and request.path
        return (
            request.url.scheme +
            COLON + SLASH + SLASH +
            request.host +
            COLON +
            str(request.port).encode() +
            request.path
        )
