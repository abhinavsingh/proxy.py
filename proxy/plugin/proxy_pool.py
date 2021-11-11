# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import random
import socket
import logging

from typing import Dict, List, Optional, Any, Tuple

from ..core.connection.server import TcpServerConnection
from ..common.types import Readables, Writables
from ..common.flag import flags
from ..common.constants import COMMA
from ..http.exception import HttpProtocolException
from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser
from ..http.methods import httpMethods

logger = logging.getLogger(__name__)

DEFAULT_HTTP_ACCESS_LOG_FORMAT = '{client_ip}:{client_port} - ' + \
    '{request_method} {server_host}:{server_port}{request_path} -> ' + \
    '{upstream_proxy_host}:{upstream_proxy_port} - ' + \
    '{response_code} {response_reason} - {response_bytes} bytes - ' + \
    '{connection_time_ms} ms'

DEFAULT_HTTPS_ACCESS_LOG_FORMAT = '{client_ip}:{client_port} - ' + \
    '{request_method} {server_host}:{server_port} -> ' + \
    '{upstream_proxy_host}:{upstream_proxy_port} - ' + \
    '{response_bytes} bytes - {connection_time_ms} ms'

# Run two separate instances of proxy.py
# on port 9000 and 9001 BUT WITHOUT ProxyPool plugin
# to avoid infinite loops.
DEFAULT_PROXY_POOL = [
    # 'localhost:9000',
    # 'localhost:9001',
]

flags.add_argument(
    '--proxy-pool',
    action='append',
    nargs=1,
    default=DEFAULT_PROXY_POOL,
    help='List of upstream proxies to create a pool',
)


class ProxyPoolPlugin(HttpProxyBasePlugin):
    """Proxy pool plugin simply acts as a proxy adapter for proxy.py itself.

    Imagine this plugin as setting up proxy settings for proxy.py instance itself.
    All incoming client requests are proxied to configured upstream proxies."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.upstream: Optional[TcpServerConnection] = None
        # Cached attributes to be used during access log override
        self.request_host_port_path_method: List[Any] = [
            None, None, None, None,
        ]
        self.total_size = 0

    def get_descriptors(self) -> Tuple[List[socket.socket], List[socket.socket]]:
        if not self.upstream:
            return [], []
        return [self.upstream.connection], [self.upstream.connection] if self.upstream.has_buffer() else []

    def read_from_descriptors(self, r: Readables) -> bool:
        # Read from upstream proxy and queue for client
        if self.upstream and self.upstream.connection in r:
            try:
                raw = self.upstream.recv(self.flags.server_recvbuf_size)
                if raw is not None:
                    self.total_size += len(raw)
                    self.client.queue(raw)
                else:
                    return True     # Teardown because upstream proxy closed the connection
            except ConnectionResetError:
                logger.debug('Connection reset by upstream proxy')
                return True
        return False    # Do not teardown connection

    def write_to_descriptors(self, w: Writables) -> bool:
        # Flush queued data to upstream proxy now
        if self.upstream and self.upstream.connection in w and self.upstream.has_buffer():
            try:
                self.upstream.flush()
            except BrokenPipeError:
                logger.debug('BrokenPipeError when flushing to upstream proxy')
                return True
        return False

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        """Avoids establishing the default connection to upstream server
        by returning None.
        """
        # TODO(abhinavsingh): Ideally connection to upstream proxy endpoints
        # must be bootstrapped within it's own re-usable and gc'd pool, to avoid establishing
        # a fresh upstream proxy connection for each client request.
        #
        # Implement your own logic here e.g. round-robin, least connection etc.
        endpoint = random.choice(self.flags.proxy_pool)[0].split(':')
        logger.debug('Using endpoint: {0}:{1}'.format(*endpoint))
        self.upstream = TcpServerConnection(
            endpoint[0], int(endpoint[1]),
        )
        try:
            self.upstream.connect()
        except ConnectionRefusedError:
            # TODO(abhinavsingh): Try another choice, when all (or max configured) choices have
            # exhausted, retry for configured number of times before giving up.
            #
            # Failing upstream proxies, must be removed from the pool temporarily.
            # A periodic health check must put them back in the pool.  This can be achieved
            # using a datastructure without having to spawn separate thread/process for health
            # check.
            logger.info(
                'Connection refused by upstream proxy {0}:{1}'.format(
                    *endpoint,
                ),
            )
            raise HttpProtocolException()
        logger.debug(
            'Established connection to upstream proxy {0}:{1}'.format(
                *endpoint,
            ),
        )
        return None

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        """Only invoked once after client original proxy request has been received completely."""
        assert self.upstream
        # For log sanity (i.e. to avoid None:None), expose upstream host:port from headers
        host, port = None, None
        # Browser or applications may sometime send
        # CONNECT / HTTP/1.0\r\n\r\n
        # for proxy keep alive check
        if request.has_header(b'host'):
            parts = request.header(b'host').decode().split(':')
            if len(parts) == 2:
                host, port = parts[0], parts[1]
            else:
                assert len(parts) == 1
                host = parts[0]
                port = '443' if request.is_https_tunnel() else '80'
        path = None if not request.path else request.path.decode()
        self.request_host_port_path_method = [
            host, port, path, request.method,
        ]
        # Queue original request to upstream proxy
        self.upstream.queue(memoryview(request.build(for_proxy=True)))
        return request

    def handle_client_data(self, raw: memoryview) -> Optional[memoryview]:
        """Only invoked when before_upstream_connection returns None"""
        # Queue data to the proxy endpoint
        assert self.upstream
        self.upstream.queue(raw)
        return raw

    def on_upstream_connection_close(self) -> None:
        """Called when client connection has been closed."""
        if self.upstream and not self.upstream.closed:
            logger.debug('Closing upstream proxy connection')
            self.upstream.close()
            self.upstream = None

    def on_access_log(self, context: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        addr, port = (
            self.upstream.addr[0], self.upstream.addr[1],
        ) if self.upstream else (None, None)
        context.update({
            'upstream_proxy_host': addr,
            'upstream_proxy_port': port,
            'server_host': self.request_host_port_path_method[0],
            'server_port': self.request_host_port_path_method[1],
            'request_path': self.request_host_port_path_method[2],
            'response_bytes': self.total_size,
        })
        self.access_log(context)
        return None

    def access_log(self, log_attrs: Dict[str, Any]) -> None:
        access_log_format = DEFAULT_HTTPS_ACCESS_LOG_FORMAT
        request_method = self.request_host_port_path_method[3]
        if request_method and request_method != httpMethods.CONNECT:
            access_log_format = DEFAULT_HTTP_ACCESS_LOG_FORMAT
        logger.info(access_log_format.format_map(log_attrs))

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        """Will never be called since we didn't establish an upstream connection."""
        raise Exception("This should have never been called")
