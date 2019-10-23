# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.exception import HttpRequestRejected
from proxy.http.parser import HttpParser
from proxy.http.codes import httpStatusCodes


class FilterByUpstreamHostPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    FILTERED_DOMAINS = [b'google.com', b'www.google.com']

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        if request.host in self.FILTERED_DOMAINS:
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot',
                headers={
                    b'Connection': b'close',
                }
            )
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
