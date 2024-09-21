# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser


class TlsInterceptConditionallyPlugin(HttpProxyBasePlugin):
    """TLS intercept conditionally."""

    def do_intercept(self, request: HttpParser) -> bool:
        if request.host == b'httpbin.org':
            return False
        return super().do_intercept(request)
