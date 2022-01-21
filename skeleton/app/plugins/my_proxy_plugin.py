# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       ip
"""
from typing import Optional

from proxy.http import httpStatusCodes
from proxy.http.proxy import HttpProxyBasePlugin
from proxy.http.parser import HttpParser
from proxy.http.exception import HttpRequestRejected


class MyProxyPlugin(HttpProxyBasePlugin):
    """Drop traffic by inspecting incoming client IP address."""

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        assert not self.flags.unix_socket_path and self.client.addr
        if self.client.addr[0] in '127.0.0.1,::1'.split(','):
            raise HttpRequestRejected(
                status_code=httpStatusCodes.I_AM_A_TEAPOT,
                reason=b'I\'m a tea pot',
            )
        return request
