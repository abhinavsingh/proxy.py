"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import os
import tempfile
import time
from typing import Optional, BinaryIO, List, Tuple
from urllib import parse as urlparse

import proxy


class ModifyPostDataPlugin(proxy.HttpProxyBasePlugin):
    """Modify POST request body before sending to upstream server."""

    MODIFIED_BODY = b'{"key": "modified"}'

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        if request.method == proxy.httpMethods.POST:
            request.body = ModifyPostDataPlugin.MODIFIED_BODY
            # Update Content-Length header only when request is NOT chunked encoded
            if not request.is_chunked_encoded():
                request.add_header(b'Content-Length', proxy.bytes_(len(request.body)))
            # Enforce content-type json
            if request.has_header(b'Content-Type'):
                request.del_header(b'Content-Type')
            request.add_header(b'Content-Type', b'application/json')
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass


class ProposedRestApiPlugin(proxy.HttpProxyBasePlugin):
    """Mock responses for your upstream REST API.

    Used to test and develop client side applications
    without need of an actual upstream REST API server.

    Returns proposed REST API mock responses to the client
    without establishing upstream connection.

    Note: This plugin won't work if your client is making
    HTTPS connection to api.example.com.
    """

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

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        # Return None to disable establishing connection to upstream
        # Most likely our api.example.com won't even exist under development scenario
        return None

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        if request.host != self.API_SERVER:
            return request
        assert request.path
        if request.path in self.REST_API_SPEC:
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.OK,
                reason=b'OK',
                headers={b'Content-Type': b'application/json'},
                body=proxy.bytes_(json.dumps(
                    self.REST_API_SPEC[request.path]))
            ))
        else:
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.NOT_FOUND,
                reason=b'NOT FOUND', body=b'Not Found'
            ))
        return None

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass


class RedirectToCustomServerPlugin(proxy.HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = b'http://localhost:8899/'

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        # Redirect all non-https requests to inbuilt WebServer.
        if request.method != proxy.httpMethods.CONNECT:
            request.set_url(self.UPSTREAM_SERVER)
            # Update Host header too, otherwise upstream can reject our request
            if request.has_header(b'Host'):
                request.del_header(b'Host')
            request.add_header(b'Host', urlparse.urlsplit(self.UPSTREAM_SERVER).netloc)
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass


class FilterByUpstreamHostPlugin(proxy.HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    FILTERED_DOMAINS = [b'google.com', b'www.google.com']

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        if request.host in self.FILTERED_DOMAINS:
            raise proxy.HttpRequestRejected(
                status_code=proxy.httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot')
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass


class CacheResponsesPlugin(proxy.HttpProxyBasePlugin):
    """Caches Upstream Server Responses."""

    CACHE_DIR = tempfile.gettempdir()

    def __init__(
            self,
            config: proxy.ProtocolConfig,
            client: proxy.TcpClientConnection) -> None:
        super().__init__(config, client)
        self.cache_file_path: Optional[str] = None
        self.cache_file: Optional[BinaryIO] = None

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        # Ideally should only create file if upstream connection succeeds.
        self.cache_file_path = os.path.join(
            self.CACHE_DIR,
            '%s-%s.txt' % (proxy.text_(request.host), str(time.time())))
        self.cache_file = open(self.cache_file_path, "wb")
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self,
                              chunk: bytes) -> bytes:
        if self.cache_file:
            self.cache_file.write(chunk)
        return chunk

    def on_upstream_connection_close(self) -> None:
        if self.cache_file:
            self.cache_file.close()
        proxy.logger.info('Cached response at %s', self.cache_file_path)


class ManInTheMiddlePlugin(proxy.HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return proxy.build_http_response(
            proxy.httpStatusCodes.OK,
            reason=b'OK', body=b'Hello from man in the middle')

    def on_upstream_connection_close(self) -> None:
        pass


class WebServerPlugin(proxy.HttpWebServerBasePlugin):
    """Demonstration of inbuilt web server routing via plugin."""

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (proxy.httpProtocolTypes.HTTP, b'/http-route-example'),
            (proxy.httpProtocolTypes.HTTPS, b'/https-route-example'),
            (proxy.httpProtocolTypes.WEBSOCKET, b'/ws-route-example'),
        ]

    def handle_request(self, request: proxy.HttpParser) -> None:
        if request.path == b'/http-route-example':
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.OK, body=b'HTTP route response'))
        elif request.path == b'/https-route-example':
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.OK, body=b'HTTPS route response'))

    def on_websocket_open(self) -> None:
        proxy.logger.info('Websocket open')

    def on_websocket_message(self, frame: proxy.WebsocketFrame) -> None:
        proxy.logger.info(frame.data)

    def on_websocket_close(self) -> None:
        proxy.logger.info('Websocket close')
