"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import List

from core.web_server import HttpWebServerBasePlugin, httpProtocolTypes
from core.websocket import WebsocketFrame
from core.http_parser import HttpParser
from core.status_codes import httpStatusCodes
from core.utils import build_http_response

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
