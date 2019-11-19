"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import json
import logging
from typing import List, Tuple, Any, Dict

from .plugin import ProxyDashboardWebsocketPlugin

from ..common.utils import build_http_response, bytes_
from ..http.server import HttpWebServerPlugin, HttpWebServerBasePlugin, httpProtocolTypes
from ..http.parser import HttpParser
from ..http.websocket import WebsocketFrame
from ..http.codes import httpStatusCodes

logger = logging.getLogger(__name__)


class ProxyDashboard(HttpWebServerBasePlugin):
    """Proxy Dashboard."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.plugins: Dict[str, ProxyDashboardWebsocketPlugin] = {}
        if b'ProxyDashboardWebsocketPlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'ProxyDashboardWebsocketPlugin']:
                p = klass(self.flags, self.client, self.event_queue)
                for method in p.methods():
                    self.plugins[method] = p

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

        method = message['method']
        if method == 'ping':
            self.reply({'id': message['id'], 'response': 'pong'})
        elif method in self.plugins:
            self.plugins[method].handle_message(message)
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
