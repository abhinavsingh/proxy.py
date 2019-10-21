# -*- coding: utf-8 -*-
"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from core.http_proxy import HttpProxyBasePlugin, HttpRequestRejected
from core.http_parser import HttpParser
from core.status_codes import httpStatusCodes


class FilterByUpstreamHostPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    FILTERED_DOMAINS = [b'google.com', b'www.google.com']

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        if request.host in self.FILTERED_DOMAINS:
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot')
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
