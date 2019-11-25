# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import gzip
import time
import logging
import os
import mimetypes
import socket
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, NamedTuple, Dict, Union, Any

from .exception import HttpProtocolException
from .websocket import WebsocketFrame, websocketOpcodes
from .codes import httpStatusCodes
from .parser import HttpParser, httpParserStates, httpParserTypes
from .handler import HttpProtocolHandlerPlugin

from ..common.utils import bytes_, text_, build_http_response, build_websocket_handshake_response
from ..common.flags import Flags
from ..common.constants import PROXY_AGENT_HEADER_VALUE
from ..common.types import HasFileno
from ..core.connection import TcpClientConnection
from ..core.event import EventQueue

logger = logging.getLogger(__name__)


HttpProtocolTypes = NamedTuple('HttpProtocolTypes', [
    ('HTTP', int),
    ('HTTPS', int),
    ('WEBSOCKET', int),
])
httpProtocolTypes = HttpProtocolTypes(1, 2, 3)


class HttpWebServerBasePlugin(ABC):
    """Web Server Plugin for routing of requests."""

    def __init__(
            self,
            uid: str,
            flags: Flags,
            client: TcpClientConnection,
            event_queue: EventQueue):
        self.uid = uid
        self.flags = flags
        self.client = client
        self.event_queue = event_queue

    @abstractmethod
    def routes(self) -> List[Tuple[int, bytes]]:
        """Return List(protocol, path) that this plugin handles."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def handle_request(self, request: HttpParser) -> None:
        """Handle the request and serve response."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_open(self) -> None:
        """Called when websocket handshake has finished."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        """Handle websocket frame."""
        raise NotImplementedError()     # pragma: no cover

    @abstractmethod
    def on_websocket_close(self) -> None:
        """Called when websocket connection has been closed."""
        raise NotImplementedError()     # pragma: no cover


class HttpWebServerPacFilePlugin(HttpWebServerBasePlugin):

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pac_file_response: Optional[memoryview] = None
        self.cache_pac_file_response()

    def routes(self) -> List[Tuple[int, bytes]]:
        if self.flags.pac_file_url_path:
            return [
                (httpProtocolTypes.HTTP, bytes_(self.flags.pac_file_url_path)),
                (httpProtocolTypes.HTTPS, bytes_(self.flags.pac_file_url_path)),
            ]
        return []   # pragma: no cover

    def handle_request(self, request: HttpParser) -> None:
        if self.flags.pac_file and self.pac_file_response:
            self.client.queue(self.pac_file_response)

    def on_websocket_open(self) -> None:
        pass    # pragma: no cover

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass    # pragma: no cover

    def on_websocket_close(self) -> None:
        pass    # pragma: no cover

    def cache_pac_file_response(self) -> None:
        if self.flags.pac_file:
            try:
                with open(self.flags.pac_file, 'rb') as f:
                    content = f.read()
            except IOError:
                content = bytes_(self.flags.pac_file)
            self.pac_file_response = memoryview(build_http_response(
                200, reason=b'OK', headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                    b'Content-Encoding': b'gzip',
                }, body=gzip.compress(content)
            ))


class HttpWebServerPlugin(HttpProtocolHandlerPlugin):
    """HttpProtocolHandler plugin which handles incoming requests to local web server."""

    DEFAULT_404_RESPONSE = memoryview(build_http_response(
        httpStatusCodes.NOT_FOUND,
        reason=b'NOT FOUND',
        headers={b'Server': PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'}
    ))

    DEFAULT_501_RESPONSE = memoryview(build_http_response(
        httpStatusCodes.NOT_IMPLEMENTED,
        reason=b'NOT IMPLEMENTED',
        headers={b'Server': PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'}
    ))

    def __init__(
            self,
            *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.start_time: float = time.time()
        self.pipeline_request: Optional[HttpParser] = None
        self.switched_protocol: Optional[int] = None
        self.routes: Dict[int, Dict[bytes, HttpWebServerBasePlugin]] = {
            httpProtocolTypes.HTTP: {},
            httpProtocolTypes.HTTPS: {},
            httpProtocolTypes.WEBSOCKET: {},
        }
        self.route: Optional[HttpWebServerBasePlugin] = None

        if b'HttpWebServerBasePlugin' in self.flags.plugins:
            for klass in self.flags.plugins[b'HttpWebServerBasePlugin']:
                instance = klass(
                    self.uid,
                    self.flags,
                    self.client,
                    self.event_queue)
                for (protocol, path) in instance.routes():
                    self.routes[protocol][path] = instance

    @staticmethod
    def read_and_build_static_file_response(path: str) -> memoryview:
        with open(path, 'rb') as f:
            content = f.read()
        content_type = mimetypes.guess_type(path)[0]
        if content_type is None:
            content_type = 'text/plain'
        return memoryview(build_http_response(
            httpStatusCodes.OK,
            reason=b'OK',
            headers={
                b'Content-Type': bytes_(content_type),
                b'Cache-Control': b'max-age=86400',
                b'Content-Encoding': b'gzip',
                b'Connection': b'close',
            },
            body=gzip.compress(content)))

    def serve_file_or_404(self, path: str) -> bool:
        """Read and serves a file from disk.

        Queues 404 Not Found for IOError.
        Shouldn't this be server error?
        """
        try:
            self.client.queue(
                self.read_and_build_static_file_response(path))
        except IOError:
            self.client.queue(self.DEFAULT_404_RESPONSE)
        return True

    def try_upgrade(self) -> bool:
        if self.request.has_header(b'connection') and \
                self.request.header(b'connection').lower() == b'upgrade':
            if self.request.has_header(b'upgrade') and \
                    self.request.header(b'upgrade').lower() == b'websocket':
                self.client.queue(
                    build_websocket_handshake_response(
                        WebsocketFrame.key_to_accept(
                            self.request.header(b'Sec-WebSocket-Key'))))
                self.switched_protocol = httpProtocolTypes.WEBSOCKET
            else:
                self.client.queue(self.DEFAULT_501_RESPONSE)
                return True
        return False

    def on_request_complete(self) -> Union[socket.socket, bool]:
        if self.request.has_upstream_server():
            return False

        # If a websocket route exists for the path, try upgrade
        if self.request.path in self.routes[httpProtocolTypes.WEBSOCKET]:
            self.route = self.routes[httpProtocolTypes.WEBSOCKET][self.request.path]

            # Connection upgrade
            teardown = self.try_upgrade()
            if teardown:
                return True

            # For upgraded connections, nothing more to do
            if self.switched_protocol:
                # Invoke plugin.on_websocket_open
                self.route.on_websocket_open()
                return False

        # Routing for Http(s) requests
        protocol = httpProtocolTypes.HTTPS \
            if self.flags.encryption_enabled() else \
            httpProtocolTypes.HTTP
        for r in self.routes[protocol]:
            if r == self.request.path:
                self.route = self.routes[protocol][r]
                self.route.handle_request(self.request)
                return False

        # No-route found, try static serving if enabled
        if self.flags.enable_static_server:
            path = text_(self.request.path).split('?')[0]
            if os.path.isfile(self.flags.static_server_dir + path):
                return self.serve_file_or_404(
                    self.flags.static_server_dir + path)

        # Catch all unhandled web server requests, return 404
        self.client.queue(self.DEFAULT_404_RESPONSE)
        return True

    def write_to_descriptors(self, w: List[Union[int, HasFileno]]) -> bool:
        pass

    def read_from_descriptors(self, r: List[Union[int, HasFileno]]) -> bool:
        pass

    def on_client_data(self, raw: memoryview) -> Optional[memoryview]:
        if self.switched_protocol == httpProtocolTypes.WEBSOCKET:
            # TODO(abhinavsingh): Remove .tobytes after websocket frame parser is memoryview compliant
            remaining = raw.tobytes()
            frame = WebsocketFrame()
            while remaining != b'':
                # TODO: Teardown if invalid protocol exception
                remaining = frame.parse(remaining)
                for r in self.routes[httpProtocolTypes.WEBSOCKET]:
                    if r == self.request.path:
                        route = self.routes[httpProtocolTypes.WEBSOCKET][r]
                        if frame.opcode == websocketOpcodes.CONNECTION_CLOSE:
                            logger.warning(
                                'Client sent connection close packet')
                            raise HttpProtocolException()
                        else:
                            route.on_websocket_message(frame)
                frame.reset()
            return None
        # If 1st valid request was completed and it's a HTTP/1.1 keep-alive
        # And only if we have a route, parse pipeline requests
        elif self.request.state == httpParserStates.COMPLETE and \
                self.request.is_http_1_1_keep_alive() and \
                self.route is not None:
            if self.pipeline_request is None:
                self.pipeline_request = HttpParser(
                    httpParserTypes.REQUEST_PARSER)
            # TODO(abhinavsingh): Remove .tobytes after parser is memoryview compliant
            self.pipeline_request.parse(raw.tobytes())
            if self.pipeline_request.state == httpParserStates.COMPLETE:
                self.route.handle_request(self.pipeline_request)
                if not self.pipeline_request.is_http_1_1_keep_alive():
                    logger.error(
                        'Pipelined request is not keep-alive, will teardown request...')
                    raise HttpProtocolException()
                self.pipeline_request = None
        return raw

    def on_response_chunk(self, chunk: List[memoryview]) -> List[memoryview]:
        return chunk

    def on_client_connection_close(self) -> None:
        if self.request.has_upstream_server():
            return
        if self.switched_protocol:
            # Invoke plugin.on_websocket_close
            for r in self.routes[httpProtocolTypes.WEBSOCKET]:
                if r == self.request.path:
                    self.routes[httpProtocolTypes.WEBSOCKET][r].on_websocket_close()
        self.access_log()

    def access_log(self) -> None:
        logger.info(
            '%s:%s - %s %s - %.2f ms' %
            (self.client.addr[0],
             self.client.addr[1],
             text_(self.request.method),
             text_(self.request.path),
             (time.time() - self.start_time) * 1000))

    def get_descriptors(
            self) -> Tuple[List[socket.socket], List[socket.socket]]:
        return [], []
