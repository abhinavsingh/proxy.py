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

from .transformer import CoreEventsToDevtoolsProtocol
from ..parser import HttpParser
from ..websocket import WebsocketFrame, websocketOpcodes
from ..server import HttpWebServerBasePlugin, httpProtocolTypes

from ...common.utils import bytes_, text_
from ...core.event import EventSubscriber

logger = logging.getLogger(__name__)


class DevtoolsProtocolPlugin(HttpWebServerBasePlugin):
    """Speaks DevTools protocol with client over websocket.

    - It responds to DevTools client request methods and also
      relay proxy.py core events to the client.
    - Core events are transformed into DevTools protocol format before
      dispatching to client.
    - Core events unrelated to DevTools protocol are dropped.
    """

    DOC_URL = 'http://dashboard.proxy.py'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.subscriber = EventSubscriber(self.event_queue)

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.WEBSOCKET, text_(self.flags.devtools_ws_path))
        ]

    def handle_request(self, request: HttpParser) -> None:
        raise NotImplementedError('This should have never been called')

    def on_websocket_open(self) -> None:
        self.subscriber.subscribe(
            lambda event: CoreEventsToDevtoolsProtocol.transformer(self.client, event))

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        try:
            assert frame.data
            message = json.loads(frame.data)
        except UnicodeDecodeError:
            logger.error(frame.data)
            logger.info(frame.opcode)
            return
        self.handle_devtools_message(message)

    def on_websocket_close(self) -> None:
        self.subscriber.unsubscribe()

    def handle_devtools_message(self, message: Dict[str, Any]) -> None:
        frame = WebsocketFrame()
        frame.fin = True
        frame.opcode = websocketOpcodes.TEXT_FRAME

        # logger.info(message)
        method = message['method']
        if method in (
            'Page.canScreencast',
            'Network.canEmulateNetworkConditions',
            'Emulation.canEmulate',
        ):
            data: Dict[str, Any] = {
                'result': False
            }
        elif method == 'Page.getResourceTree':
            data = {
                'result': {
                    'frameTree': {
                        'frame': {
                            'id': 1,
                            'url': DevtoolsProtocolPlugin.DOC_URL,
                            'mimeType': 'other',
                        },
                        'childFrames': [],
                        'resources': []
                    }
                }
            }
        elif method == 'Network.getResponseBody':
            connection_id = message['params']['requestId']
            data = {
                'result': {
                    'body': text_(CoreEventsToDevtoolsProtocol.RESPONSES[connection_id]),
                    'base64Encoded': False,
                }
            }
        else:
            logging.warning('Unhandled devtools method %s', method)
            data = {}

        data['id'] = message['id']
        frame.data = bytes_(json.dumps(data))
        self.client.queue(memoryview(frame.build()))
