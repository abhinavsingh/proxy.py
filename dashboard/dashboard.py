"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import json
import logging
from typing import List, Tuple, Any, Dict

from proxy.core.event import EventSubscriber
from proxy.http.server import HttpWebServerPlugin, HttpWebServerBasePlugin, httpProtocolTypes
from proxy.http.parser import HttpParser
from proxy.http.websocket import WebsocketFrame
from proxy.http.codes import httpStatusCodes
from proxy.common.utils import build_http_response, bytes_
from proxy.core.connection import TcpClientConnection

logger = logging.getLogger(__name__)


class ProxyDashboard(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.subscriber = EventSubscriber(self.event_queue)
        self.inspection_enabled: bool = False

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            # Redirects to /dashboard/
            (httpProtocolTypes.HTTP, b'/dashboard'),
            # Redirects to /dashboard/
            (httpProtocolTypes.HTTPS, b'/dashboard'),
            # Redirects to /dashboard/
            (httpProtocolTypes.HTTP, b'/dashboard/proxy.html'),
            # Redirects to /dashboard/
            (httpProtocolTypes.HTTPS, b'/dashboard/proxy.html'),
            (httpProtocolTypes.HTTP, b'/dashboard/'),
            (httpProtocolTypes.HTTPS, b'/dashboard/'),
            (httpProtocolTypes.WEBSOCKET, b'/dashboard'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        if request.path == b'/dashboard/':
            self.client.queue(
                HttpWebServerPlugin.read_and_build_static_file_response(
                    os.path.join(self.flags.static_server_dir, 'dashboard', 'proxy.html')))
        elif request.path in (
                b'/dashboard',
                b'/dashboard/proxy.html'):
            self.client.queue(build_http_response(
                httpStatusCodes.PERMANENT_REDIRECT, reason=b'Permanent Redirect',
                headers={
                    b'Location': b'/dashboard/',
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
            self.reply({'id': message['id'], 'response': 'pong'})
        elif message['method'] == 'enable_inspection':
            # inspection can only be enabled if --enable-events is used
            if not self.flags.enable_events:
                self.client.queue(
                    WebsocketFrame.text(
                        bytes_(
                            json.dumps(
                                {'id': message['id'], 'response': 'not enabled'})
                        )
                    )
                )
            else:
                self.inspection_enabled = True
                self.subscriber.subscribe(
                    lambda event: ProxyDashboard.callback(
                        self.client, event))
                self.reply(
                    {'id': message['id'], 'response': 'inspection_enabled'})
        elif message['method'] == 'disable_inspection':
            self.subscriber.unsubscribe()
            self.inspection_enabled = False
            self.reply({'id': message['id'],
                        'response': 'inspection_disabled'})
        else:
            logger.info(frame.data)
            logger.info(frame.opcode)
            self.reply({'id': message['id'], 'response': 'not_implemented'})

    def on_websocket_close(self) -> None:
        logger.info('app ws closed')
        # unsubscribe

    def reply(self, data: Dict[str, Any]) -> None:
        self.client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps(data))))

    @staticmethod
    def callback(client: TcpClientConnection, event: Dict[str, Any]) -> None:
        event['push'] = 'inspect_traffic'
        client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps(event))))
