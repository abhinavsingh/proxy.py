# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import json
import logging
import secrets
import time
from typing import List, Tuple, Any, Dict

from .parser import HttpParser
from .websocket import WebsocketFrame, websocketOpcodes
from .server import HttpWebServerBasePlugin, httpProtocolTypes

from ..common.constants import PROXY_PY_START_TIME
from ..common.utils import bytes_
from ..core.connection import TcpClientConnection
from ..core.event import EventSubscriber, eventNames

logger = logging.getLogger(__name__)


class DevtoolsProtocolPlugin(HttpWebServerBasePlugin):
    """Speaks DevTools protocol with client over websocket."""

    DOC_URL = 'http://dashboard.proxy.py'
    FRAME_ID = secrets.token_hex(8)
    LOADER_ID = secrets.token_hex(8)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.subscriber = EventSubscriber(self.event_queue)

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.WEBSOCKET, self.flags.devtools_ws_path)
        ]

    def handle_request(self, request: HttpParser) -> None:
        raise NotImplementedError('This should have never been called')

    def on_websocket_open(self) -> None:
        self.subscriber.subscribe(
            lambda event: DevtoolsProtocolPlugin.transformer(self.client, event))

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

        method = message['method']
        data: Dict[str, Any] = {}

        if method in (
            'Page.canScreencast',
            'Network.canEmulateNetworkConditions',
            'Emulation.canEmulate'
        ):
            data = {
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
            data = {
                'result': {
                    'body': '',
                    'base64Encoded': False,
                }
            }
        else:
            logging.warning('Unhandled devtools method %s', method)
            data = {
                'result': {},
            }

        data['id'] = message['id']
        frame.data = bytes_(json.dumps(data))
        self.client.queue(frame.build())

    @staticmethod
    def transformer(client: TcpClientConnection,
                    event: Dict[str, Any]) -> None:
        event_name = event['event_name']
        if event_name == eventNames.REQUEST_COMPLETE:
            pass
        elif event_name == eventNames.RESPONSE_HEADERS_COMPLETE:
            pass
        elif event_name == eventNames.RESPONSE_CHUNK_RECEIVED:
            pass
        elif event_name == eventNames.RESPONSE_COMPLETE:
            pass
        else:
            # drop the event, unrelated to Devtools
            pass
        client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps(event))))

    def request_will_be_sent(self) -> Dict[str, Any]:
        now = time.time()
        return {
            # 'requestId': self.id,
            'frameId': DevtoolsProtocolPlugin.FRAME_ID,
            'loaderId': DevtoolsProtocolPlugin.LOADER_ID,
            'documentURL': 'http://proxy-py',
            'request': {
                # 'url': text_(
                # self.request.path
                # if self.request.has_upstream_server() else
                # b'http://' + bytes_(str(self.config.hostname)) +
                # COLON + bytes_(self.config.port) + self.request.path
                # ),
                'urlFragment': '',
                # 'method': text_(self.request.method),
                # 'headers': {text_(v[0]): text_(v[1]) for v in self.request.headers.values()},
                'initialPriority': 'High',
                'mixedContentType': 'none',
                # 'postData': None if self.request.method != 'POST'
                # else text_(self.request.body)
            },
            'timestamp': now - PROXY_PY_START_TIME,
            'wallTime': now,
            'initiator': {
                'type': 'other'
            },
            # 'type': text_(self.request.header(b'content-type'))
            # if self.request.has_header(b'content-type')
            # else 'Other',
            'hasUserGesture': False
        }

    def response_received(self) -> Dict[str, Any]:
        return {
            # 'requestId': self.id,
            'frameId': DevtoolsProtocolPlugin.FRAME_ID,
            'loaderId': DevtoolsProtocolPlugin.LOADER_ID,
            'timestamp': time.time(),
            # 'type': text_(self.response.header(b'content-type'))
            # if self.response.has_header(b'content-type')
            # else 'Other',
            'response': {
                'url': '',
                'status': '',
                'statusText': '',
                'headers': '',
                'headersText': '',
                'mimeType': '',
                'connectionReused': True,
                'connectionId': '',
                'encodedDataLength': '',
                'fromDiskCache': False,
                'fromServiceWorker': False,
                'timing': {
                    'requestTime': '',
                    'proxyStart': -1,
                    'proxyEnd': -1,
                    'dnsStart': -1,
                    'dnsEnd': -1,
                    'connectStart': -1,
                    'connectEnd': -1,
                    'sslStart': -1,
                    'sslEnd': -1,
                    'workerStart': -1,
                    'workerReady': -1,
                    'sendStart': 0,
                    'sendEnd': 0,
                    'receiveHeadersEnd': 0,
                },
                'requestHeaders': '',
                'remoteIPAddress': '',
                'remotePort': '',
            }
        }

    def data_received(self, chunk: bytes) -> Dict[str, Any]:
        return {
            # 'requestId': self.id,
            'timestamp': time.time(),
            'dataLength': len(chunk),
            'encodedDataLength': len(chunk),
        }

    def loading_finished(self) -> Dict[str, Any]:
        return {
            # 'requestId': self.id,
            'timestamp': time.time(),
            # 'encodedDataLength': self.response.total_size
        }
