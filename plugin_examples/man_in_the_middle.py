# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from proxy.http_proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.status_codes import httpStatusCodes
from proxy.common.utils import build_http_response


class ManInTheMiddlePlugin(HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return build_http_response(
            httpStatusCodes.OK,
            reason=b'OK', body=b'Hello from man in the middle')

    def on_upstream_connection_close(self) -> None:
        pass
