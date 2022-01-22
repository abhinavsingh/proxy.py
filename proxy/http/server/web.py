# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import re
import time
import socket
import logging
import mimetypes
from typing import Any, Dict, List, Tuple, Union, Pattern, Optional

from .plugin import HttpWebServerBasePlugin
from ..parser import HttpParser, httpParserTypes
from ..plugin import HttpProtocolHandlerPlugin
from .protocols import httpProtocolTypes
from ..exception import HttpProtocolException
from ..protocols import httpProtocols
from ..responses import NOT_FOUND_RESPONSE_PKT, okResponse
from ..websocket import WebsocketFrame, websocketOpcodes
from ...common.flag import flags
from ...common.types import Readables, Writables, Descriptors
from ...common.utils import text_, bytes_, build_websocket_handshake_response
from ...common.constants import (
    DEFAULT_ENABLE_WEB_SERVER, DEFAULT_STATIC_SERVER_DIR,
    DEFAULT_ENABLE_REVERSE_PROXY, DEFAULT_ENABLE_STATIC_SERVER,
    DEFAULT_MIN_COMPRESSION_LIMIT, DEFAULT_WEB_ACCESS_LOG_FORMAT,
)


logger = logging.getLogger(__name__)


flags.add_argument(
    '--enable-web-server',
    action='store_true',
    default=DEFAULT_ENABLE_WEB_SERVER,
    help='Default: False.  Whether to enable proxy.HttpWebServerPlugin.',
)

flags.add_argument(
    '--enable-static-server',
    action='store_true',
    default=DEFAULT_ENABLE_STATIC_SERVER,
    help='Default: False.  Enable inbuilt static file server. '
    'Optionally, also use --static-server-dir to serve static content '
    'from custom directory.  By default, static file server serves '
    'out of installed proxy.py python module folder.',
)

flags.add_argument(
    '--static-server-dir',
    type=str,
    default=DEFAULT_STATIC_SERVER_DIR,
    help='Default: "public" folder in directory where proxy.py is placed. '
    'This option is only applicable when static server is also enabled. '
    'See --enable-static-server.',
)

flags.add_argument(
    '--min-compression-length',
    type=int,
    default=DEFAULT_MIN_COMPRESSION_LIMIT,
    help='Default: ' + str(DEFAULT_MIN_COMPRESSION_LIMIT) + ' bytes.  ' +
    'Sets the minimum length of a response that will be compressed (gzipped).',
)

flags.add_argument(
    '--enable-reverse-proxy',
    action='store_true',
    default=DEFAULT_ENABLE_REVERSE_PROXY,
    help='Default: False.  Whether to enable reverse proxy core.',
)


class HttpWebServerPlugin(HttpProtocolHandlerPlugin):
    """HttpProtocolHandler plugin which handles incoming requests to local web server."""

    def __init__(
            self,
            *args: Any, **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.start_time: float = time.time()
        self.pipeline_request: Optional[HttpParser] = None
        self.switched_protocol: Optional[int] = None
        self.route: Optional[HttpWebServerBasePlugin] = None

        self.plugins: Dict[str, HttpWebServerBasePlugin] = {}
        self.routes: Dict[
            int, Dict[Pattern[str], HttpWebServerBasePlugin],
        ] = {
            httpProtocolTypes.HTTP: {},
            httpProtocolTypes.HTTPS: {},
            httpProtocolTypes.WEBSOCKET: {},
        }
        if b'HttpWebServerBasePlugin' in self.flags.plugins:
            self._initialize_web_plugins()

    @staticmethod
    def protocols() -> List[int]:
        return [httpProtocols.WEB_SERVER]

    def _initialize_web_plugins(self) -> None:
        for klass in self.flags.plugins[b'HttpWebServerBasePlugin']:
            instance: HttpWebServerBasePlugin = klass(
                self.uid,
                self.flags,
                self.client,
                self.event_queue,
                self.upstream_conn_pool,
            )
            self.plugins[instance.name()] = instance
            for (protocol, route) in instance.routes():
                pattern = re.compile(route)
                self.routes[protocol][pattern] = self.plugins[instance.name()]

    def encryption_enabled(self) -> bool:
        return self.flags.keyfile is not None and \
            self.flags.certfile is not None

    @staticmethod
    def read_and_build_static_file_response(path: str) -> memoryview:
        try:
            with open(path, 'rb') as f:
                content = f.read()
            content_type = mimetypes.guess_type(path)[0]
            if content_type is None:
                content_type = 'text/plain'
            headers = {
                b'Content-Type': bytes_(content_type),
                b'Cache-Control': b'max-age=86400',
            }
            return okResponse(
                content=content,
                headers=headers,
                # TODO: Should we really close or take advantage of keep-alive?
                conn_close=True,
            )
        except FileNotFoundError:
            return NOT_FOUND_RESPONSE_PKT

    def switch_to_websocket(self) -> None:
        self.client.queue(
            memoryview(
                build_websocket_handshake_response(
                    WebsocketFrame.key_to_accept(
                        self.request.header(b'Sec-WebSocket-Key'),
                    ),
                ),
            ),
        )
        self.switched_protocol = httpProtocolTypes.WEBSOCKET

    def on_request_complete(self) -> Union[socket.socket, bool]:
        path = self.request.path or b'/'
        teardown = self._try_route(path)
        # Try route signaled to teardown
        # or if it did find a valid route
        if teardown or self.route is not None:
            return teardown
        # No-route found, try static serving if enabled
        if self.flags.enable_static_server:
            self._try_static_or_404(path)
            return True
        # Catch all unhandled web server requests, return 404
        self.client.queue(NOT_FOUND_RESPONSE_PKT)
        return True

    async def get_descriptors(self) -> Descriptors:
        r, w = [], []
        for plugin in self.plugins.values():
            r1, w1 = await plugin.get_descriptors()
            r.extend(r1)
            w.extend(w1)
        return r, w

    async def write_to_descriptors(self, w: Writables) -> bool:
        for plugin in self.plugins.values():
            teardown = await plugin.write_to_descriptors(w)
            if teardown:
                return True
        return False

    async def read_from_descriptors(self, r: Readables) -> bool:
        for plugin in self.plugins.values():
            teardown = await plugin.read_from_descriptors(r)
            if teardown:
                return True
        return False

    def on_client_data(self, raw: memoryview) -> Optional[memoryview]:
        if self.switched_protocol == httpProtocolTypes.WEBSOCKET:
            # TODO(abhinavsingh): Remove .tobytes after websocket frame parser
            # is memoryview compliant
            remaining = raw.tobytes()
            frame = WebsocketFrame()
            while remaining != b'':
                # TODO: Tear down if invalid protocol exception
                remaining = frame.parse(remaining)
                if frame.opcode == websocketOpcodes.CONNECTION_CLOSE:
                    raise HttpProtocolException(
                        'Client sent connection close packet',
                    )
                else:
                    assert self.route
                    self.route.on_websocket_message(frame)
                frame.reset()
            return None
        # If 1st valid request was completed and it's a HTTP/1.1 keep-alive
        # And only if we have a route, parse pipeline requests
        if self.request.is_complete and \
                self.request.is_http_1_1_keep_alive and \
                self.route is not None:
            if self.pipeline_request is None:
                self.pipeline_request = HttpParser(
                    httpParserTypes.REQUEST_PARSER,
                )
            # TODO(abhinavsingh): Remove .tobytes after parser is memoryview
            # compliant
            self.pipeline_request.parse(raw.tobytes())
            if self.pipeline_request.is_complete:
                self.route.handle_request(self.pipeline_request)
                if not self.pipeline_request.is_http_1_1_keep_alive:
                    raise HttpProtocolException(
                        'Pipelined request is not keep-alive, will tear down request...',
                    )
                self.pipeline_request = None
        return raw

    def on_response_chunk(self, chunk: List[memoryview]) -> List[memoryview]:
        return chunk

    def on_client_connection_close(self) -> None:
        context = {
            'client_ip': None if not self.client.addr else self.client.addr[0],
            'client_port': None if not self.client.addr else self.client.addr[1],
            'connection_time_ms': '%.2f' % ((time.time() - self.start_time) * 1000),
            # Request
            'request_method': text_(self.request.method),
            'request_path': text_(self.request.path),
            'request_bytes': self.request.total_size,
            'request_ua': text_(self.request.header(b'user-agent'))
            if self.request.has_header(b'user-agent')
            else None,
            'request_version': None if not self.request.version else text_(self.request.version),
            # Response
            #
            # TODO: Track and inject web server specific response attributes
            # Currently, plugins are allowed to queue raw bytes, because of
            # which we'll have to reparse the queued packets to deduce
            # several attributes required below.  At least for code and
            # reason attributes.
            #
            # 'response_bytes': self.response.total_size,
            # 'response_code': text_(self.response.code),
            # 'response_reason': text_(self.response.reason),
        }
        log_handled = False
        if self.route:
            # May be merge on_client_connection_close and on_access_log???
            # probably by simply deprecating on_client_connection_close in future.
            self.route.on_client_connection_close()
            ctx = self.route.on_access_log(context)
            if ctx is None:
                log_handled = True
            else:
                context = ctx
        if not log_handled:
            self.access_log(context)

    def access_log(self, context: Dict[str, Any]) -> None:
        logger.info(DEFAULT_WEB_ACCESS_LOG_FORMAT.format_map(context))

    @property
    def _protocol(self) -> Tuple[bool, int]:
        do_ws_upgrade = self.request.is_connection_upgrade and \
            self.request.header(b'upgrade').lower() == b'websocket'
        return do_ws_upgrade, httpProtocolTypes.WEBSOCKET \
            if do_ws_upgrade \
            else httpProtocolTypes.HTTPS \
            if self.encryption_enabled() \
            else httpProtocolTypes.HTTP

    def _try_route(self, path: bytes) -> bool:
        do_ws_upgrade, protocol = self._protocol
        for route in self.routes[protocol]:
            if route.match(text_(path)):
                self.route = self.routes[protocol][route]
                assert self.route
                # Optionally, upgrade protocol
                if do_ws_upgrade:
                    self.switch_to_websocket()
                    assert self.route
                    # Invoke plugin.on_websocket_open
                    self.route.on_websocket_open()
                else:
                    # Invoke plugin.handle_request
                    self.route.handle_request(self.request)
                    if self.request.has_header(b'connection') and \
                            self.request.header(b'connection').lower() == b'close':
                        return True
        return False

    def _try_static_or_404(self, path: bytes) -> None:
        path = text_(path).split('?', 1)[0]
        self.client.queue(
            self.read_and_build_static_file_response(
                self.flags.static_server_dir + path,
            ),
        )
