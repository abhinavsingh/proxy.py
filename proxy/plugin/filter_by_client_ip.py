# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from ..common.flag import flags
from ..http.exception import HttpRequestRejected
from ..http.parser import HttpParser, httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin


flags.add_argument(
    '--filtered-client-ips',
    type=str,
    default='127.0.0.1,::1',
    help='Default: 127.0.0.1,::1.  Comma separated list of IPv4 and IPv6 addresses.',
)


class FilterByClientIpPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting incoming client IP address."""

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        assert not self.flags.unix_socket_path and self.client.addr
        if self.client.addr[0] in self.flags.filtered_client_ips.split(','):
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot',
                headers={
                    b'Connection': b'close',
                },
            )
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
