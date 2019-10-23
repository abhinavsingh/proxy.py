# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import threading
import queue
import socket
import time
import secrets
import os
import logging
import json
from typing import Optional, Union, List, Tuple, Dict, Any

from .common.utils import bytes_, text_
from .common.flags import Flags
from .http.parser import httpParserStates, httpParserTypes, HttpParser
from .core.connection import TcpClientConnection
from .http.server import HttpWebServerBasePlugin, httpProtocolTypes
from .http.websocket import WebsocketFrame, websocketOpcodes
from .common.constants import COLON, PROXY_PY_START_TIME
from .common.types import HasFileno, DictQueueType
from .http.handler import HttpProtocolHandlerPlugin

logger = logging.getLogger(__name__)


class DevtoolsWebsocketPlugin(HttpWebServerBasePlugin):
    """DevtoolsWebsocketPlugin handles Devtools Frontend websocket requests.

    For every connected Devtools Frontend instance, a dispatcher thread is
    started which drains the global Devtools protocol events queue.

    Dispatcher thread is terminated when Devtools Frontend disconnects."""

    def __init__(
            self,
            config: Flags,
            client: TcpClientConnection):
        super().__init__(config, client)
        self.event_dispatcher_thread: Optional[threading.Thread] = None
        self.event_dispatcher_shutdown: Optional[threading.Event] = None

    def start_dispatcher(self) -> None:
        self.event_dispatcher_shutdown = threading.Event()
        assert self.config.devtools_event_queue is not None
        self.event_dispatcher_thread = threading.Thread(
            target=DevtoolsWebsocketPlugin.event_dispatcher,
            args=(self.event_dispatcher_shutdown,
                  self.config.devtools_event_queue,
                  self.client))
        self.event_dispatcher_thread.start()

    def stop_dispatcher(self) -> None:
        assert self.event_dispatcher_shutdown is not None
        assert self.event_dispatcher_thread is not None
        self.event_dispatcher_shutdown.set()
        self.event_dispatcher_thread.join()
        logger.debug('Event dispatcher shutdown')

    @staticmethod
    def event_dispatcher(
            shutdown: threading.Event,
            devtools_event_queue: DictQueueType,
            client: TcpClientConnection) -> None:
        while not shutdown.is_set():
            try:
                ev = devtools_event_queue.get(timeout=1)
                frame = WebsocketFrame()
                frame.fin = True
                frame.opcode = websocketOpcodes.TEXT_FRAME
                frame.data = bytes_(json.dumps(ev))
                logger.debug(ev)
                client.queue(frame.build())
            except queue.Empty:
                pass
            except Exception as e:
                logger.exception('Event dispatcher exception', exc_info=e)
                break
            except KeyboardInterrupt:
                break

    def routes(self) -> List[Tuple[int, bytes]]:
        return [
            (httpProtocolTypes.WEBSOCKET, self.config.devtools_ws_path)
        ]

    def handle_request(self, request: HttpParser) -> None:
        pass

    def on_websocket_open(self) -> None:
        self.start_dispatcher()

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        if frame.data:
            message = json.loads(frame.data)
            self.handle_message(message)
        else:
            logger.debug('No data found in frame')

    def on_websocket_close(self) -> None:
        self.stop_dispatcher()

    def handle_message(self, message: Dict[str, Any]) -> None:
        frame = WebsocketFrame()
        frame.fin = True
        frame.opcode = websocketOpcodes.TEXT_FRAME

        if message['method'] in (
                'Page.canScreencast',
                'Network.canEmulateNetworkConditions',
                'Emulation.canEmulate'
        ):
            data = json.dumps({
                'id': message['id'],
                'result': False
            })
        elif message['method'] == 'Page.getResourceTree':
            data = json.dumps({
                'id': message['id'],
                'result': {
                    'frameTree': {
                        'frame': {
                            'id': 1,
                            'url': 'http://proxypy',
                            'mimeType': 'other',
                        },
                        'childFrames': [],
                        'resources': []
                    }
                }
            })
        elif message['method'] == 'Network.getResponseBody':
            logger.debug('received request method Network.getResponseBody')
            data = json.dumps({
                'id': message['id'],
                'result': {
                    'body': '',
                    'base64Encoded': False,
                }
            })
        else:
            data = json.dumps({
                'id': message['id'],
                'result': {},
            })

        frame.data = bytes_(data)
        self.client.queue(frame.build())


class DevtoolsProtocolPlugin(HttpProtocolHandlerPlugin):
    """
    DevtoolsProtocolPlugin taps into core `ProtocolHandler`
    events and converts them into Devtools Protocol json messages.

    A DevtoolsProtocolPlugin instance is created per request.
    Per request devtool events are queued into a global multiprocessing queue.
    """

    frame_id = secrets.token_hex(8)
    loader_id = secrets.token_hex(8)

    def __init__(
            self,
            config: Flags,
            client: TcpClientConnection,
            request: HttpParser):
        self.id: str = f'{ os.getpid() }-{ threading.get_ident() }-{ time.time() }'
        self.response = HttpParser(httpParserTypes.RESPONSE_PARSER)
        super().__init__(config, client, request)

    def get_descriptors(self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []

    def write_to_descriptors(self, w: List[Union[int, HasFileno]]) -> bool:
        return False

    def read_from_descriptors(self, r: List[Union[int, HasFileno]]) -> bool:
        return False

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        return raw

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if not self.request.has_upstream_server() and \
                self.request.path == self.config.devtools_ws_path:
            return False

        # Handle devtool frontend websocket upgrade
        if self.config.devtools_event_queue:
            self.config.devtools_event_queue.put({
                'method': 'Network.requestWillBeSent',
                'params': self.request_will_be_sent(),
            })
        return False

    def on_response_chunk(self, chunk: bytes) -> bytes:
        if not self.request.has_upstream_server() and \
                self.request.path == self.config.devtools_ws_path:
            return chunk

        if self.config.devtools_event_queue:
            self.response.parse(chunk)
            if self.response.state >= httpParserStates.HEADERS_COMPLETE:
                self.config.devtools_event_queue.put({
                    'method': 'Network.responseReceived',
                    'params': self.response_received(),
                })
            if self.response.state >= httpParserStates.RCVING_BODY:
                self.config.devtools_event_queue.put({
                    'method': 'Network.dataReceived',
                    'params': self.data_received(chunk)
                })
            if self.response.state == httpParserStates.COMPLETE:
                self.config.devtools_event_queue.put({
                    'method': 'Network.loadingFinished',
                    'params': self.loading_finished()
                })
        return chunk

    def on_client_connection_close(self) -> None:
        pass

    def request_will_be_sent(self) -> Dict[str, Any]:
        now = time.time()
        return {
            'requestId': self.id,
            'loaderId': self.loader_id,
            'documentURL': 'http://proxy-py',
            'request': {
                'url': text_(
                    self.request.path
                    if self.request.has_upstream_server() else
                    b'http://' + bytes_(str(self.config.hostname)) +
                    COLON + bytes_(self.config.port) + self.request.path
                ),
                'urlFragment': '',
                'method': text_(self.request.method),
                'headers': {text_(v[0]): text_(v[1]) for v in self.request.headers.values()},
                'initialPriority': 'High',
                'mixedContentType': 'none',
                'postData': None if self.request.method != 'POST'
                else text_(self.request.body)
            },
            'timestamp': now - PROXY_PY_START_TIME,
            'wallTime': now,
            'initiator': {
                'type': 'other'
            },
            'type': text_(self.request.header(b'content-type'))
            if self.request.has_header(b'content-type')
            else 'Other',
            'frameId': self.frame_id,
            'hasUserGesture': False
        }

    def response_received(self) -> Dict[str, Any]:
        return {
            'requestId': self.id,
            'frameId': self.frame_id,
            'loaderId': self.loader_id,
            'timestamp': time.time(),
            'type': text_(self.response.header(b'content-type'))
            if self.response.has_header(b'content-type')
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

    def data_received(self, chunk: bytes) -> Dict[str, Any]:
        return {
            'requestId': self.id,
            'timestamp': time.time(),
            'dataLength': len(chunk),
            'encodedDataLength': len(chunk),
        }

    def loading_finished(self) -> Dict[str, Any]:
        return {
            'requestId': self.id,
            'timestamp': time.time(),
            'encodedDataLength': self.response.total_size
        }
