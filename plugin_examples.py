"""
    proxy.py
    ~~~~~~~~
    Lightweight Programmable HTTP, HTTPS, WebSockets Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh.
    :license: BSD, see LICENSE for more details.
"""

from urllib import parse as urlparse

import proxy


class RedirectToCustomServerPlugin(proxy.HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    def __init__(self, config: proxy.HttpProtocolConfig, client: proxy.TcpClientConnection,
                 request: proxy.HttpParser) -> None:
        super().__init__(config, client, request)

    def before_upstream_connection(self) -> None:
        # Redirect all non-https requests to inbuilt WebServer.
        if self.request.method != b'CONNECT':
            self.request.url = urlparse.urlsplit(b'http://localhost:8899')

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw


class FilterByTargetDomainPlugin(proxy.HttpProxyBasePlugin):
    """Only accepts specific requests dropping all other requests."""

    def __init__(self, config: proxy.HttpProtocolConfig, client: proxy.TcpClientConnection,
                 request: proxy.HttpParser) -> None:
        super().__init__(config, client, request)
        self.filtered_domain = b'google.com'

    def before_upstream_connection(self) -> None:
        if self.filtered_domain == self.request.host:
            raise proxy.HttpRequestRejected(status_code=418, body=b'I\'m a tea pot')

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw


class CacheHttpResponses(proxy.HttpProxyBasePlugin):
    """Caches Http Responses."""

    def __init__(self, config: proxy.HttpProtocolConfig, client: proxy.TcpClientConnection,
                 request: proxy.HttpParser) -> None:
        super().__init__(config, client, request)

    def before_upstream_connection(self) -> None:
        pass

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, chunk: bytes) -> bytes:
        return chunk
