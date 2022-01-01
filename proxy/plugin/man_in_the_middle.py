# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from ..http.responses import okResponse
from ..http.proxy import HttpProxyBasePlugin


class ManInTheMiddlePlugin(HttpProxyBasePlugin):
    """Modifies upstream server responses."""

    def handle_upstream_chunk(self, _chunk: memoryview) -> memoryview:
        return okResponse(content=b'Hello from man in the middle')
