# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time
import socket
import selectors
from typing import Any, Optional, Dict

from proxy.proxy import Proxy
from proxy.core.acceptor import AcceptorPool
from proxy.core.connection import TcpServerConnection
from proxy.http.parser import HttpParser, httpParserTypes, httpParserStates
from proxy.http.codes import httpStatusCodes
from proxy.http.methods import httpMethods
from proxy.common.types import Readables, Writables
from proxy.common.utils import build_http_response, text_

from examples.base_server import BaseServerHandler


class ConnectTunnelHandler(BaseServerHandler):  # type: ignore
    """A http CONNECT tunnel server."""

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = memoryview(build_http_response(
        httpStatusCodes.OK,
        reason=b'Connection established'
    ))

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.request = HttpParser(httpParserTypes.REQUEST_PARSER)
        self.upstream: Optional[TcpServerConnection] = None

    def initialize(self) -> None:
        self.client.connection.setblocking(False)

    def shutdown(self) -> None:
        if self.upstream:
            print('Connection closed with upstream {0}:{1}'.format(
                text_(self.request.host), self.request.port))
            self.upstream.close()
        super().shutdown()

    def handle_data(self, data: memoryview) -> None:
        # Queue for upstream if connection has been established
        if self.upstream and self.upstream._conn is not None:
            self.upstream.queue(data)
            return

        # Parse client request
        self.request.parse(data)

        # Drop the request if not a CONNECT request
        if self.request.method != httpMethods.CONNECT:
            pass

        # CONNECT requests are short and we need not worry about
        # receiving partial request bodies here.
        assert self.request.state == httpParserStates.COMPLETE

        # Establish connection with upstream
        self.connect_upstream()

        # Queue tunnel established response to client
        self.client.queue(
            ConnectTunnelHandler.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)

    def get_events(self) -> Dict[socket.socket, int]:
        # Get default client events
        ev: Dict[socket.socket, int] = super().get_events()
        # Read from server if we are connected
        if self.upstream and self.upstream._conn is not None:
            ev[self.upstream.connection] = selectors.EVENT_READ
        # If there is pending buffer for server
        # also register for EVENT_WRITE events
        if self.upstream and self.upstream.has_buffer():
            if self.upstream.connection in ev:
                ev[self.upstream.connection] |= selectors.EVENT_WRITE
            else:
                ev[self.upstream.connection] = selectors.EVENT_WRITE
        return ev

    def handle_events(
            self,
            readables: Readables,
            writables: Writables) -> bool:
        # Handle client events
        do_shutdown: bool = super().handle_events(readables, writables)
        if do_shutdown:
            return do_shutdown
        # Handle server events
        if self.upstream and self.upstream.connection in readables:
            data = self.upstream.recv()
            if data is None:
                # Server closed connection
                print('Connection closed by server')
                return True
            # tunnel data to client
            self.client.queue(data)
        if self.upstream and self.upstream.connection in writables:
            self.upstream.flush()
        return False

    def connect_upstream(self) -> None:
        assert self.request.host and self.request.port
        self.upstream = TcpServerConnection(
            text_(self.request.host), self.request.port)
        self.upstream.connect()
        print('Connection established with upstream {0}:{1}'.format(
            text_(self.request.host), self.request.port))


def main() -> None:
    # This example requires `threadless=True`
    pool = AcceptorPool(
        flags=Proxy.initialize(port=12345, num_workers=1, threadless=True),
        work_klass=ConnectTunnelHandler)
    try:
        pool.setup()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        pool.shutdown()


if __name__ == '__main__':
    main()
