# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import logging
import os
import mimetypes
import socket
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, NamedTuple, Dict, Union

from .exception import HttpProtocolException
from .websocket import WebsocketFrame, websocketOpcodes
from .codes import httpStatusCodes
from .parser import HttpParser, httpParserStates, httpParserTypes

from ..common.utils import bytes_, text_, build_http_response, build_websocket_handshake_response
from ..common.flags import Flags
from ..common.constants import PROXY_AGENT_HEADER_VALUE
from ..common.types import HasFileno
from ..core.connection import TcpClientConnection

from ..protocol_handler import ProtocolHandlerPlugin

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
            config: Flags,
            client: TcpClientConnection):
        self.config = config
        self.client = client

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

    def __init__(
            self,
            config: Flags,
            client: TcpClientConnection):
        super().__init__(config, client)
        self.pac_file_response: Optional[bytes] = None
        self.cache_pac_file_response()

    def cache_pac_file_response(self) -> None:
        if self.config.pac_file:
            try:
                with open(self.config.pac_file, 'rb') as f:
                    content = f.read()
            except IOError:
                content = bytes_(self.config.pac_file)
            self.pac_file_response = build_http_response(
                200, reason=b'OK', headers={
                    b'Content-Type': b'application/x-ns-proxy-autoconfig',
                }, body=content
            )

    def routes(self) -> List[Tuple[int, bytes]]:
        if self.config.pac_file_url_path:
            return [
                (httpProtocolTypes.HTTP, bytes_(self.config.pac_file_url_path)),
                (httpProtocolTypes.HTTPS, bytes_(self.config.pac_file_url_path)),
            ]
        return []   # pragma: no cover

    def handle_request(self, request: HttpParser) -> None:
        if self.config.pac_file and self.pac_file_response:
            self.client.queue(self.pac_file_response)

    def on_websocket_open(self) -> None:
        pass    # pragma: no cover

    def on_websocket_message(self, frame: WebsocketFrame) -> None:
        pass    # pragma: no cover

    def on_websocket_close(self) -> None:
        pass    # pragma: no cover


class HttpWebServerPlugin(ProtocolHandlerPlugin):
    """ProtocolHandler plugin which handles incoming requests to local web server."""

    DEFAULT_404_RESPONSE = build_http_response(
        httpStatusCodes.NOT_FOUND,
        reason=b'NOT FOUND',
        headers={b'Server': PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'}
    )

    DEFAULT_501_RESPONSE = build_http_response(
        httpStatusCodes.NOT_IMPLEMENTED,
        reason=b'NOT IMPLEMENTED',
        headers={b'Server': PROXY_AGENT_HEADER_VALUE,
                 b'Connection': b'close'}
    )

    def __init__(
            self,
            config: Flags,
            client: TcpClientConnection,
            request: HttpParser):
        super().__init__(config, client, request)
        self.start_time: float = time.time()
        self.pipeline_request: Optional[HttpParser] = None
        self.switched_protocol: Optional[int] = None
        self.routes: Dict[int, Dict[bytes, HttpWebServerBasePlugin]] = {
            httpProtocolTypes.HTTP: {},
            httpProtocolTypes.HTTPS: {},
            httpProtocolTypes.WEBSOCKET: {},
        }
        self.route: Optional[HttpWebServerBasePlugin] = None

        if b'HttpWebServerBasePlugin' in self.config.plugins:
            for klass in self.config.plugins[b'HttpWebServerBasePlugin']:
                instance = klass(self.config, self.client)
                for (protocol, path) in instance.routes():
                    self.routes[protocol][path] = instance

    @staticmethod
    def read_and_build_static_file_response(path: str) -> bytes:
        with open(path, 'rb') as f:
            content = f.read()
        content_type = mimetypes.guess_type(path)[0]
        if content_type is None:
            content_type = 'text/plain'
        return build_http_response(
            httpStatusCodes.OK,
            reason=b'OK',
            headers={
                b'Content-Type': bytes_(content_type),
                b'Connection': b'close',
            },
            body=content)

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
            if self.config.encryption_enabled() else \
            httpProtocolTypes.HTTP
        for r in self.routes[protocol]:
            if r == self.request.path:
                self.route = self.routes[protocol][r]
                self.route.handle_request(self.request)
                return False

        # No-route found, try static serving if enabled
        if self.config.enable_static_server:
            path = text_(self.request.path).split('?')[0]
            if os.path.isfile(self.config.static_server_dir + path):
                return self.serve_file_or_404(self.config.static_server_dir + path)

        # Catch all unhandled web server requests, return 404
        self.client.queue(self.DEFAULT_404_RESPONSE)
        return True

    def write_to_descriptors(self, w: List[Union[int, HasFileno]]) -> bool:
        pass

    def read_from_descriptors(self, r: List[Union[int, HasFileno]]) -> bool:
        pass

    def on_client_data(self, raw: bytes) -> Optional[bytes]:
        if self.switched_protocol == httpProtocolTypes.WEBSOCKET:
            remaining = raw
            frame = WebsocketFrame()
            while remaining != b'':
                # TODO: Teardown if invalid protocol exception
                remaining = frame.parse(remaining)
                for r in self.routes[httpProtocolTypes.WEBSOCKET]:
                    if r == self.request.path:
                        route = self.routes[httpProtocolTypes.WEBSOCKET][r]
                        if frame.opcode == websocketOpcodes.CONNECTION_CLOSE:
                            logger.warning('Client sent connection close packet')
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
                self.pipeline_request = HttpParser(httpParserTypes.REQUEST_PARSER)
            self.pipeline_request.parse(raw)
            if self.pipeline_request.state == httpParserStates.COMPLETE:
                self.route.handle_request(self.pipeline_request)
                if not self.pipeline_request.is_http_1_1_keep_alive():
                    logger.error('Pipelined request is not keep-alive, will teardown request...')
                    raise HttpProtocolException()
                self.pipeline_request = None
        return raw

    def on_response_chunk(self, chunk: bytes) -> bytes:
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
