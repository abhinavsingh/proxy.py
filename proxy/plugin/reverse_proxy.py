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
from typing import List, Tuple
from urllib import parse as urlparse

from ..common.constants import DEFAULT_BUFFER_SIZE, DEFAULT_HTTP_PORT
from ..common.utils import socket_connection, text_
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes


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
          "url": "https://localhost/get"
        }
    """

    REVERSE_PROXY_LOCATION: str = r'/get$'
    REVERSE_PROXY_PASS = [
        b'http://httpbin.org/get'
    ]

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, ReverseProxyPlugin.REVERSE_PROXY_LOCATION),
            (httpProtocolTypes.HTTPS, ReverseProxyPlugin.REVERSE_PROXY_LOCATION)
        ]

    # TODO(abhinavsingh): Upgrade to use non-blocking get/read/write API.
    def handle_request(self, request: HttpParser) -> None:
        upstream = random.choice(ReverseProxyPlugin.REVERSE_PROXY_PASS)
        url = urlparse.urlsplit(upstream)
        assert url.hostname
        with socket_connection((text_(url.hostname), url.port or DEFAULT_HTTP_PORT)) as conn:
            conn.send(request.build())
            self.client.queue(memoryview(conn.recv(DEFAULT_BUFFER_SIZE)))

    def on_websocket_open(self) -> None:
        pass

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass

    def on_websocket_close(self) -> None:
        pass
