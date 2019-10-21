"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    app.py extends proxy.py APIs to provide a frontend dashboard
    available at http://localhost:8899/index.html
"""

import json
from typing import List, Tuple

import proxy


class ProxyDashboard(proxy.HttpWebServerBasePlugin):

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (proxy.httpProtocolTypes.HTTP, b'/'),
            (proxy.httpProtocolTypes.HTTPS, b'/'),
            (proxy.httpProtocolTypes.HTTP, b'/proxy.html'),
            (proxy.httpProtocolTypes.HTTPS, b'/proxy.html'),
            (proxy.httpProtocolTypes.WEBSOCKET, b'/app'),
        ]

    def handle_request(self, request: proxy.HttpParser) -> None:
        if request.path == b'/':
            self.client.queue(
                proxy.HttpWebServerPlugin.read_and_build_static_file_response(
                    self.config.static_server_dir + proxy.text_(b'/proxy.html')))
        elif request.path == b'/proxy.html':
            self.client.queue(proxy.build_http_response(
                proxy.httpStatusCodes.PERMANENT_REDIRECT, reason=b'Permanent Redirect',
                headers={
                    b'Location': b'/',
                    b'Content-Length': b'0',
                    b'Connection': b'close',
                }
            ))

    def on_websocket_open(self) -> None:
        proxy.logger.info('app ws opened')

    def on_websocket_message(self, frame: proxy.WebsocketFrame) -> None:
        try:
            message = json.loads(frame.data)
        except UnicodeDecodeError:
            proxy.logger.error(frame.data)
            proxy.logger.info(frame.opcode)
            return

        if message['method'] == 'ping':
            self.reply_pong(message['id'])
        else:
            proxy.logger.info(frame.data)
            proxy.logger.info(frame.opcode)

    def on_websocket_close(self) -> None:
        proxy.logger.info('app ws closed')

    def reply_pong(self, idd: int):
        self.client.queue(
            proxy.WebsocketFrame.text(
                proxy.bytes_(
                    json.dumps({'id': idd, 'response': 'pong'}))))
