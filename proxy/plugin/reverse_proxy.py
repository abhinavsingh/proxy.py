# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import ssl
import random
import socket
import logging

from typing import List, Optional, Tuple, Any
from urllib import parse as urlparse

from ..common.utils import text_
from ..common.constants import DEFAULT_HTTPS_PORT, DEFAULT_HTTP_PORT
from ..common.types import Readables, Writables
from ..core.connection import TcpServerConnection
from ..http.exception import HttpProtocolException
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes

logger = logging.getLogger(__name__)


# TODO: ReverseProxyPlugin and ProxyPoolPlugin are implementing
# a similar behavior.  Abstract that particular logic out into its
# own class.
class ReverseProxyPlugin(HttpWebServerBasePlugin):
    """Extend in-built Web Server to add Reverse Proxy capabilities.

    This example plugin is equivalent to following Nginx configuration:

        location /get {
            proxy_pass http://httpbin.org/get
        }

    Example:

        $ curl http://localhost:9000/get
        {
          "args": {},
          "headers": {
            "Accept": "*/*",
            "Host": "localhost",
            "User-Agent": "curl/7.64.1"
          },
          "origin": "1.2.3.4, 5.6.7.8",
          "url": "http://localhost/get"
        }
    """

    # TODO: We must use nginx python parser and
    # make this plugin nginx.conf complaint.
    REVERSE_PROXY_LOCATION: str = r'/get$'
    # Randomly choose either http or https upstream endpoint.
    #
    # This is just to demonstrate that both http and https upstream
    # reverse proxy works.
    REVERSE_PROXY_PASS = [
        b'http://httpbin.org/get',
        b'https://httpbin.org/get',
    ]

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.upstream: Optional[TcpServerConnection] = None

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, ReverseProxyPlugin.REVERSE_PROXY_LOCATION),
            (httpProtocolTypes.HTTPS, ReverseProxyPlugin.REVERSE_PROXY_LOCATION),
        ]

    def get_descriptors(self) -> Tuple[List[socket.socket], List[socket.socket]]:
        if not self.upstream:
            return [], []
        return [self.upstream.connection], [self.upstream.connection] if self.upstream.has_buffer() else []

    def read_from_descriptors(self, r: Readables) -> bool:
        if self.upstream and self.upstream.connection in r:
            try:
                raw = self.upstream.recv(self.flags.server_recvbuf_size)
                if raw is not None:
                    self.client.queue(raw)
                else:
                    return True     # Teardown because upstream server closed the connection
            except ssl.SSLWantReadError:
                logger.info('Upstream server SSLWantReadError, will retry')
                return False
            except ConnectionResetError:
                logger.debug('Connection reset by upstream server')
                return True
        return super().read_from_descriptors(r)

    def write_to_descriptors(self, w: Writables) -> bool:
        if self.upstream and self.upstream.connection in w and self.upstream.has_buffer():
            try:
                self.upstream.flush()
            except ssl.SSLWantWriteError:
                logger.info('Upstream server SSLWantWriteError, will retry')
                return False
            except BrokenPipeError:
                logger.debug(
                    'BrokenPipeError when flushing to upstream server',
                )
                return True
        return super().write_to_descriptors(w)

    def handle_request(self, request: HttpParser) -> None:
        url = urlparse.urlsplit(
            random.choice(ReverseProxyPlugin.REVERSE_PROXY_PASS),
        )
        assert url.hostname
        port = url.port or (
            DEFAULT_HTTP_PORT if url.scheme ==
            b'http' else DEFAULT_HTTPS_PORT
        )
        self.upstream = TcpServerConnection(text_(url.hostname), port)
        try:
            self.upstream.connect()
            if url.scheme == b'https':
                self.upstream.wrap(
                    text_(
                        url.hostname,
                    ), ca_file=str(self.flags.ca_file),
                )
            self.upstream.queue(memoryview(request.build()))
        except ConnectionRefusedError:
            logger.info(
                'Connection refused by upstream server {0}:{1}'.format(
                    text_(url.hostname), port,
                ),
            )
            raise HttpProtocolException()

    def on_websocket_open(self) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def on_client_connection_close(self) -> None:
        if self.upstream and not self.upstream.closed:
            logger.debug('Closing upstream server connection')
            self.upstream.close()
            self.upstream = None
