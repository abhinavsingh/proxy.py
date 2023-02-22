# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       ws
       onmessage
"""
import logging
from typing import List, Tuple

from ..http.parser import HttpParser
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from ..http.responses import okResponse
from ..http.websocket.frame import WebsocketFrame


logger = logging.getLogger(__name__)

HTTP_RESPONSE = okResponse(content=b'HTTP route response')
HTTPS_RESPONSE = okResponse(content=b'HTTPS route response')


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

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        """Open chrome devtools and try using following commands:

        Example:

            ws = new WebSocket("ws://localhost:8899/ws-route-example")
            ws.onmessage = function(m) { console.log(m); }
            ws.send('hello')

        """
        self.client.queue(memoryview(WebsocketFrame.text(frame.data or b'')))
