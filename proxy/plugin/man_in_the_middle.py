# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from ..common.utils import build_http_response
from ..http import httpStatusCodes
from ..http.proxy import HttpProxyBasePlugin


class ManInTheMiddlePlugin(HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def handle_upstream_chunk(self, chunk: memoryview) -> memoryview:
        return memoryview(
            build_http_response(
                httpStatusCodes.OK,
                reason=b'OK',
                body=b'Hello from man in the middle',
            ),
        )
