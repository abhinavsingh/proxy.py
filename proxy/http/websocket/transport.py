# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import logging
from typing import List, Tuple, Any, Dict

from ...common.utils import bytes_

from ..server import httpProtocolTypes, HttpWebServerBasePlugin
from ..parser import HttpParser

from .frame import WebsocketFrame
from .plugin import WebSocketTransportBasePlugin

logger = logging.getLogger(__name__)


class WebSocketTransport(HttpWebServerBasePlugin):
    """WebSocket transport framework."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.plugins: Dict[str, WebSocketTransportBasePlugin] = {}
        if b'WebSocketTransportBasePlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'WebSocketTransportBasePlugin']:
                p = klass(self.flags, self.client, self.event_queue)
                for method in p.methods():
                    self.plugins[method] = p

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.WEBSOCKET, r'/transport/$'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        raise NotImplementedError()

    def on_websocket_open(self) -> None:
        # TODO(abhinavsingh): Add connected callback invocation
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

    def on_client_connection_close(self) -> None:
        # TODO(abhinavsingh): Add disconnected callback invocation
        logger.info('app ws closed')

    def reply(self, data: Dict[str, Any]) -> None:
        self.client.queue(
            memoryview(
                WebsocketFrame.text(
                    bytes_(
                        json.dumps(data),
                    ),
                ),
            ),
        )
