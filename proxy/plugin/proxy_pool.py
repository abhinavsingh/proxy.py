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
import logging

from typing import List, Optional, Any, Tuple

from ..core.connection.server import TcpServerConnection
from ..common.constants import COLON, SLASH
from ..common.types import Readables, Writables
from ..http.exception import HttpProtocolException
from ..http.proxy import HttpProxyBasePlugin
from ..http.methods import httpMethods
from ..http.parser import HttpParser

logger = logging.getLogger(__name__)


class ProxyPoolPlugin(HttpProxyBasePlugin):
    """Proxy pool plugin simply acts as a proxy adapter for proxy.py itself.

    Imagine this plugin as setting up proxy settings for proxy.py instance itself.
    All incoming client requests are proxied to configured upstream proxies."""

    # Run two separate instances of proxy.py
    # on port 9000 and 9001 BUT WITHOUT ProxyPool plugin
    # to avoid infinite loops.
    UPSTREAM_PROXY_POOL = [
        ('localhost', 9000),
        ('localhost', 9001),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.upstream: Optional[TcpServerConnection] = None

    def get_descriptors(self) -> Tuple[List[socket.socket], List[socket.socket]]:
        if not self.upstream:
            return [], []
        return [self.upstream.connection], [self.upstream.connection] if self.upstream.has_buffer() else []

    def read_from_descriptors(self, r: Readables) -> bool:
        # Read from upstream proxy and queue for client
        if self.upstream and self.upstream.connection in r:
            try:
                raw = self.upstream.recv(self.flags.server_recvbuf_size)
                if raw is not None:
                    self.client.queue(raw)
                else:
                    return True     # Teardown because upstream proxy closed the connection
            except ConnectionResetError:
                logger.debug('Connection reset by upstream proxy')
                return True
        return False    # Do not teardown connection

    def write_to_descriptors(self, w: Writables) -> bool:
        # Flush queued data to upstream proxy now
        if self.upstream and self.upstream.connection in w and self.upstream.has_buffer():
            try:
                self.upstream.flush()
            except BrokenPipeError:
                logger.debug('BrokenPipeError when flushing to upstream proxy')
                return True
        return False

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Avoids establishing the default connection to upstream server
        by returning None.
        """
        # TODO(abhinavsingh): Ideally connection to upstream proxy endpoints
        # must be bootstrapped within it's own re-usable and gc'd pool, to avoid establishing
        # a fresh upstream proxy connection for each client request.
        #
        # Implement your own logic here e.g. round-robin, least connection etc.
        endpoint = random.choice(self.UPSTREAM_PROXY_POOL)
        logger.debug('Using endpoint: {0}:{1}'.format(*endpoint))
        self.upstream = TcpServerConnection(
            endpoint[0], endpoint[1])
        try:
            self.upstream.connect()
        except ConnectionRefusedError:
            logger.info('Connection refused by upstream proxy')
            raise HttpProtocolException()
        logger.debug('Established connection to upstream proxy')
        return None

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        """Only invoked once after client original proxy request has been received completely."""
        request.path = self.rebuild_original_path(request)
        assert self.upstream
        self.upstream.queue(memoryview(request.build()))
        return request

    def handle_client_data(self, raw: memoryview) -> Optional[memoryview]:
        """Only invoked when before_upstream_connection returns None"""
        # Queue data to the proxy endpoint
        assert self.upstream
        self.upstream.queue(raw)
        return raw

    def on_upstream_connection_close(self) -> None:
        """Called when client connection has been closed."""
        if self.upstream and self.upstream.connection:
            logger.debug('Closing upstream proxy connection')
            self.upstream.close()
            self.upstream = None

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
        ) if request.method != httpMethods.CONNECT else (request.host + COLON + str(request.port).encode())

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        """Will never be called since we didn't establish an upstream connection."""
        raise Exception("This should have never been called")
