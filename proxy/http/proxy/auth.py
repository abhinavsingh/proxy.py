# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling:word-list::

       auth
       http
"""
from typing import Optional

from ...http import httpHeaders
from ..exception import ProxyAuthenticationFailed
from ...http.proxy import HttpProxyBasePlugin
from ...http.parser import HttpParser


class AuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication."""

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if self.flags.auth_code and request.headers:
            if httpHeaders.PROXY_AUTHORIZATION not in request.headers:
                raise ProxyAuthenticationFailed()
            parts = request.headers[httpHeaders.PROXY_AUTHORIZATION][1].split()
            if len(parts) != 2 \
                    or parts[0].lower() != b'basic' \
                    or parts[1] != self.flags.auth_code:
                raise ProxyAuthenticationFailed()
        return request
