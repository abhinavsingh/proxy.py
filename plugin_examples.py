"""
    proxy.py
    ~~~~~~~~
    Lightweight Programmable HTTP, HTTPS, WebSockets Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""
import os
import tempfile
import time
from typing import Optional, BinaryIO
from urllib import parse as urlparse

import proxy


class RedirectToCustomServerPlugin(proxy.HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = b'http://localhost:8899'

    def before_upstream_connection(self) -> None:
        # Redirect all non-https requests to inbuilt WebServer.
        if self.request.method != b'CONNECT':
            self.request.url = urlparse.urlsplit(self.UPSTREAM_SERVER)
            self.request.set_host_port()

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw

    def on_upstream_connection_close(self) -> None:
        pass


class FilterByUpstreamHostPlugin(proxy.HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    FILTERED_DOMAINS = [b'google.com', b'www.google.com']

    def before_upstream_connection(self) -> None:
        if self.request.host in self.FILTERED_DOMAINS:
            raise proxy.HttpRequestRejected(
                status_code=418, reason=b'I\'m a tea pot')

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw

    def on_upstream_connection_close(self) -> None:
        pass


class CacheResponsesPlugin(proxy.HttpProxyBasePlugin):
    """Caches Upstream Server Responses."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(self, config: proxy.HttpProtocolConfig, client: proxy.TcpClientConnection,
                 request: proxy.HttpParser) -> None:
        super().__init__(config, client, request)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(self) -> None:
        pass

    def on_upstream_connection(self) -> None:
        self.cache_file_path = os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (proxy.text_(self.request.host), str(time.time())))
        self.cache_file = open(self.cache_file_path, "wb")

    def handle_upstream_response(self, chunk: bytes) -> bytes:
        if self.cache_file:
            self.cache_file.write(chunk)
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
        proxy.logger.info('Cached response at %s', self.cache_file_path)


class ManInTheMiddlePlugin(proxy.HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def before_upstream_connection(self) -> None:
        pass

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        body = b'Hello from man in the middle'
        response = proxy.CRLF.join([
            b'HTTP/1.1 200 OK',
            b'Content-Length: ' + proxy.bytes_(str(len(body))),
            proxy.CRLF,
        ]) + body
        return response

    def on_upstream_connection_close(self) -> None:
        pass
