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
from ..common.utils import bytes_, text_
from ..core.connection import TcpClientConnection
from ..core.event import EventSubscriber, eventNames

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
        self.client.queue(frame.build())


class CoreEventsToDevtoolsProtocol:

    RESPONSES: Dict[str, bytes] = {}

    @staticmethod
    def transformer(client: TcpClientConnection,
                    event: Dict[str, Any]) -> None:
        event_name = event['event_name']
        if event_name == eventNames.REQUEST_COMPLETE:
            data = CoreEventsToDevtoolsProtocol.request_complete(event)
        elif event_name == eventNames.RESPONSE_HEADERS_COMPLETE:
            data = CoreEventsToDevtoolsProtocol.response_headers_complete(
                event)
        elif event_name == eventNames.RESPONSE_CHUNK_RECEIVED:
            data = CoreEventsToDevtoolsProtocol.response_chunk_received(event)
        elif event_name == eventNames.RESPONSE_COMPLETE:
            data = CoreEventsToDevtoolsProtocol.response_complete(event)
        else:
            # drop core events unrelated to Devtools
            return
        client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps(data))))

    @staticmethod
    def request_complete(event: Dict[str, Any]) -> Dict[str, Any]:
        now = time.time()
        return {
            'requestId': event['request_id'],
            'frameId': DevtoolsProtocolPlugin.FRAME_ID,
            'loaderId': DevtoolsProtocolPlugin.LOADER_ID,
            'documentURL': DevtoolsProtocolPlugin.DOC_URL,
            'timestamp': now - PROXY_PY_START_TIME,
            'wallTime': now,
            'hasUserGesture': False,
            'type': event['event_payload']['headers']['content-type']
            if event['event_payload']['headers'].has_header('content-type')
            else 'Other',
            'request': {
                'url': event['event_payload']['url'],
                'method': event['event_payload']['method'],
                'headers': event['event_payload']['headers'],
                'postData': event['event_payload']['body'],
                'initialPriority': 'High',
                'urlFragment': '',
                'mixedContentType': 'none',
            },
            'initiator': {
                'type': 'other'
            },
        }

    @staticmethod
    def response_headers_complete(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'requestId': event['request_id'],
            'frameId': DevtoolsProtocolPlugin.FRAME_ID,
            'loaderId': DevtoolsProtocolPlugin.LOADER_ID,
            'timestamp': time.time(),
            'type': event['event_payload']['headers']['content-type']
            if event['event_payload']['headers'].has_header('content-type')
            else 'Other',
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

    @staticmethod
    def response_chunk_received(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'requestId': event['request_id'],
            'timestamp': time.time(),
            'dataLength': event['event_payload']['chunk_size'],
            'encodedDataLength': event['event_payload']['encoded_chunk_size'],
        }

    @staticmethod
    def response_complete(event: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'requestId': event['request_id'],
            'timestamp': time.time(),
            'encodedDataLength': event['event_payload']['encoded_response_size'],
            'shouldReportCorbBlocking': False,
        }
