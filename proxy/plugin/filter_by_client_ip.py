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

from ..http.exception import HttpRequestRejected
from ..http.parser import HttpParser
from ..http.codes import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin


class FilterByClientIpPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting incoming client IP address."""

    FILTERED_IPS = ['127.0.0.1', '::1']

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        if self.client.addr[0] in self.FILTERED_IPS:
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot',
                headers={
                    b'Connection': b'close',
                }
            )
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
