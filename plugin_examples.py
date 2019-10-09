"""
    proxy.py
    ~~~~~~~~
    Lightweight, Programmable, TLS interceptor Proxy for HTTP(S), HTTP2, WebSockets protocols in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import os
import tempfile
import time
from typing import Optional, BinaryIO, Union
from urllib import parse as urlparse

import proxy


class ProposedRestApiPlugin(proxy.HttpProxyBasePlugin):
    """Mock responses for your upstream REST API.

    Used to test and develop client side applications
    without need of an actual upstream REST API server.

    Returns proposed REST API mock responses to the client."""

    API_SERVER = b'api.example.com'

    REST_API_SPEC = {
        b'/v1/users/': {
            'count': 2,
            'next': None,
            'previous': None,
            'results': [
                {
                    'email': 'you@example.com',
                    'groups': [],
                    'url': proxy.text_(API_SERVER) + '/v1/users/1/',
                    'username': 'admin',
                },
                {
                    'email': 'someone@example.com',
                    'groups': [],
                    'url': proxy.text_(API_SERVER) + '/v1/users/2/',
                    'username': 'someone',
                },
            ]
        },
    }

    def before_upstream_connection(self) -> bool:
        """Called after client request is received and
        before connecting to upstream server."""
        if self.request.host == self.API_SERVER and self.request.url:
            if self.request.url.path in self.REST_API_SPEC:
                self.client.send(proxy.build_http_response(
                    200, reason=b'OK',
                    headers={b'Content-Type': b'application/json'},
                    body=proxy.bytes_(json.dumps(
                        self.REST_API_SPEC[self.request.url.path]))
                ))
            else:
                self.client.send(proxy.build_http_response(
                    404, reason=b'NOT FOUND', body=b'Not Found'
                ))
            return True
        return False

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw

    def on_upstream_connection_close(self) -> None:
        pass


class RedirectToCustomServerPlugin(proxy.HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = b'http://localhost:8899'

    def before_upstream_connection(self) -> bool:
        # Redirect all non-https requests to inbuilt WebServer.
        if self.request.method != proxy.httpMethods.CONNECT:
            self.request.url = urlparse.urlsplit(self.UPSTREAM_SERVER)
            self.request.set_host_port()
        return False

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw

    def on_upstream_connection_close(self) -> None:
        pass


class FilterByUpstreamHostPlugin(proxy.HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    FILTERED_DOMAINS = [b'google.com', b'www.google.com']

    def before_upstream_connection(self) -> bool:
        if self.request.host in self.FILTERED_DOMAINS:
            raise proxy.HttpRequestRejected(
                status_code=418, reason=b'I\'m a tea pot')
        return False

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return raw

    def on_upstream_connection_close(self) -> None:
        pass


class CacheResponsesPlugin(proxy.HttpProxyBasePlugin):
    """Caches Upstream Server Responses."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(self, config: proxy.ProtocolConfig, client: proxy.TcpClientConnection,
                 request: proxy.HttpParser) -> None:
        super().__init__(config, client, request)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(self) -> bool:
        return False

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

    def before_upstream_connection(self) -> bool:
        return False

    def on_upstream_connection(self) -> None:
        pass

    def handle_upstream_response(self, raw: bytes) -> bytes:
        return proxy.build_http_response(
            200, reason=b'OK', body=b'Hello from man in the middle')

    def on_upstream_connection_close(self) -> None:
        pass
