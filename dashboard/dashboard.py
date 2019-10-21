"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    app.py extends py APIs to provide a frontend dashboard
    available at http://localhost:8899/index.html
"""
import json
import logging
from typing import List, Tuple

from core.web_server import HttpWebServerPlugin, HttpWebServerBasePlugin, httpProtocolTypes
from core.http_parser import HttpParser
from core.utils import text_, build_http_response, bytes_
from core.websocket import WebsocketFrame
from core.status_codes import httpStatusCodes

logger = logging.getLogger(__name__)


class ProxyDashboard(HttpWebServerBasePlugin):

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.HTTP, b'/'),
            (httpProtocolTypes.HTTPS, b'/'),
            (httpProtocolTypes.HTTP, b'/html'),
            (httpProtocolTypes.HTTPS, b'/html'),
            (httpProtocolTypes.WEBSOCKET, b'/app'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        if request.path == b'/':
            self.client.queue(
                HttpWebServerPlugin.read_and_build_static_file_response(
                    self.config.static_server_dir + text_(b'/html')))
        elif request.path == b'/html':
            self.client.queue(build_http_response(
                httpStatusCodes.PERMANENT_REDIRECT, reason=b'Permanent Redirect',
                headers={
                    b'Location': b'/',
                    b'Content-Length': b'0',
                    b'Connection': b'close',
                }
            ))

    def on_websocket_open(self) -> None:
        logger.info('app ws opened')

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        try:
            message = json.loads(frame.data)
        except UnicodeDecodeError:
            logger.error(frame.data)
            logger.info(frame.opcode)
            return

        if message['method'] == 'ping':
            self.reply_pong(message['id'])
        else:
            logger.info(frame.data)
            logger.info(frame.opcode)

    def on_websocket_close(self) -> None:
        logger.info('app ws closed')

    def reply_pong(self, idd: int):
        self.client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps({'id': idd, 'response': 'pong'}))))
