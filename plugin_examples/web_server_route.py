# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import List, Tuple

from proxy.http.server import HttpWebServerBasePlugin, httpProtocolTypes
from proxy.http.websocket import WebsocketFrame
from proxy.http.parser import HttpParser
from proxy.http.codes import httpStatusCodes
from proxy.common.utils import build_http_response

logger = logging.getLogger(__name__)


class WebServerPlugin(HttpWebServerBasePlugin):
    """Demonstration of inbuilt web server routing via plugin."""

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.HTTP, b'/http-route-example'),
            (httpProtocolTypes.HTTPS, b'/https-route-example'),
            (httpProtocolTypes.WEBSOCKET, b'/ws-route-example'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        if request.path == b'/http-route-example':
            self.client.queue(build_http_response(
                httpStatusCodes.OK, body=b'HTTP route response'))
        elif request.path == b'/https-route-example':
            self.client.queue(build_http_response(
                httpStatusCodes.OK, body=b'HTTPS route response'))

    def on_websocket_open(self) -> None:
        logger.info('Websocket open')

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        logger.info(frame.data)

    def on_websocket_close(self) -> None:
        logger.info('Websocket close')
