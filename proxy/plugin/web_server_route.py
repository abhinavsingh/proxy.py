# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import List, Tuple

from ..common.utils import build_http_response

from ..http import httpStatusCodes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes

HTTP_RESPONSE = memoryview(
    build_http_response(
        httpStatusCodes.OK, body=b'HTTP route response',
    ),
)

HTTPS_RESPONSE = memoryview(
    build_http_response(
        httpStatusCodes.OK, body=b'HTTPS route response',
    ),
)

logger = logging.getLogger(__name__)


class WebServerPlugin(HttpWebServerBasePlugin):
    """Demonstrates inbuilt web server routing using plugin."""

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, r'/http-route-example$'),
            (httpProtocolTypes.HTTPS, r'/https-route-example$'),
            (httpProtocolTypes.WEBSOCKET, r'/ws-route-example$'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        if request.path == b'/http-route-example':
            self.client.queue(HTTP_RESPONSE)
        elif request.path == b'/https-route-example':
            self.client.queue(HTTPS_RESPONSE)

    def on_websocket_open(self) -> None:
        logger.info('Websocket open')

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        logger.info(frame.data)

    def on_client_connection_close(self) -> None:
        logger.debug('Client connection close')
