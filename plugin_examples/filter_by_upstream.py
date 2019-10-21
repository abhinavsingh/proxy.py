# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


class FilterByUpstreamHostPlugin(proxy.HttpProxyBasePlugin):
    """Drop traffic by inspecting upstream host."""

    FILTERED_DOMAINS = [b'google.com', b'www.google.com']

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        if request.host in self.FILTERED_DOMAINS:
            raise proxy.HttpRequestRejected(
                status_code=proxy.httpStatusCodes.I_AM_A_TEAPOT, reason=b'I\'m a tea pot')
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
