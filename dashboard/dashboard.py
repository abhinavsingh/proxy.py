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
import queue
import logging
import threading
import multiprocessing
import uuid
from typing import List, Tuple, Optional, Any

from proxy.http.server import HttpWebServerPlugin, HttpWebServerBasePlugin, httpProtocolTypes
from proxy.http.parser import HttpParser
from proxy.http.websocket import WebsocketFrame
from proxy.http.codes import httpStatusCodes
from proxy.common.utils import build_http_response, bytes_
from proxy.common.types import DictQueueType
from proxy.core.connection import TcpClientConnection

VERSION = (0, 1, 0)
__version__ = '.'.join(map(str, VERSION[0:3]))

logger = logging.getLogger(__name__)


class ProxyDashboard(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.inspection_enabled: bool = False
        self.relay_thread: Optional[threading.Thread] = None
        self.relay_shutdown: Optional[threading.Event] = None
        self.relay_manager: Optional[multiprocessing.managers.SyncManager] = None
        self.relay_channel: Optional[DictQueueType] = None
        self.relay_sub_id: Optional[str] = None

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
            self.reply_pong(message['id'])
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

                self.relay_shutdown = threading.Event()
                self.relay_manager = multiprocessing.Manager()
                self.relay_channel = self.relay_manager.Queue()
                self.relay_thread = threading.Thread(
                    target=self.relay_events,
                    args=(self.relay_shutdown, self.relay_channel, self.client))
                self.relay_thread.start()

                self.relay_sub_id = uuid.uuid4().hex
                self.event_queue.subscribe(
                    self.relay_sub_id, self.relay_channel)
        elif message['method'] == 'disable_inspection':
            if self.inspection_enabled:
                self.shutdown_relay()
            self.inspection_enabled = False
        else:
            logger.info(frame.data)
            logger.info(frame.opcode)

    def shutdown_relay(self) -> None:
        assert self.relay_manager
        assert self.relay_shutdown
        assert self.relay_thread

        self.relay_shutdown.set()
        self.relay_thread.join()
        self.relay_manager.shutdown()

        self.relay_manager = None
        self.relay_thread = None
        self.relay_shutdown = None
        self.relay_channel = None
        self.relay_sub_id = None

    def on_websocket_close(self) -> None:
        logger.info('app ws closed')
        if self.inspection_enabled:
            self.shutdown_relay()

    def reply_pong(self, idd: int) -> None:
        self.client.queue(
            WebsocketFrame.text(
                bytes_(
                    json.dumps({'id': idd, 'response': 'pong'}))))

    @staticmethod
    def relay_events(
            shutdown: threading.Event,
            channel: DictQueueType,
            client: TcpClientConnection) -> None:
        while not shutdown.is_set():
            try:
                ev = channel.get(timeout=1)
                client.queue(
                    WebsocketFrame.text(
                        bytes_(
                            json.dumps(ev))))
            except queue.Empty:
                pass
            except EOFError:
                break
            except KeyboardInterrupt:
                break
