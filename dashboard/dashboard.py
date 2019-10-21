"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import logging
from typing import List, Tuple

from proxy.web_server import HttpWebServerPlugin, HttpWebServerBasePlugin, httpProtocolTypes
from proxy.http_parser import HttpParser
from proxy.utils import text_, build_http_response, bytes_
from proxy.websocket import WebsocketFrame
from proxy.status_codes import httpStatusCodes

logger = logging.getLogger(__name__)


class ProxyDashboard(HttpWebServerBasePlugin):

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.HTTP, b'/'),
            (httpProtocolTypes.HTTPS, b'/'),
            (httpProtocolTypes.HTTP, b'/proxy.html'),
            (httpProtocolTypes.HTTPS, b'/proxy.html'),
            (httpProtocolTypes.WEBSOCKET, b'/app'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        if request.path == b'/':
            self.client.queue(
                HttpWebServerPlugin.read_and_build_static_file_response(
                    self.config.static_server_dir + text_(b'/proxy.html')))
        elif request.path == b'/proxy.html':
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
            assert frame.data
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

    def reply_pong(self, idd: int) -> None:
        self.client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps({'id': idd, 'response': 'pong'}))))
