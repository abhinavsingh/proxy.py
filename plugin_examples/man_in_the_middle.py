# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""


class ManInTheMiddlePlugin(proxy.HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def before_upstream_connection(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_client_request(self, request: proxy.HttpParser) -> Optional[proxy.HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return proxy.build_http_response(
            proxy.httpStatusCodes.OK,
            reason=b'OK', body=b'Hello from man in the middle')

    def on_upstream_connection_close(self) -> None:
        pass
