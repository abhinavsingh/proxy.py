# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from ..http.proxy import HttpProxyBasePlugin
from ..http.parser import HttpParser
from ..common.utils import bytes_
from ..common.version import __version__


class ModifyRequestHeaderPlugin(HttpProxyBasePlugin):
    """Modify request header before sending to upstream server."""

    # def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
    #     """NOTE: Use this for HTTP only request headers modification."""
    #     request.add_header(
    #         b"x-proxy-py-version",
    #         bytes_(__version__),
    #     )
    #     return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        """NOTE: This is for HTTPS request headers modification when under TLS interception.

        For HTTPS requests, modification of request under TLS interception WILL NOT WORK
        through before_upstream_connection.
        """
        request.add_header(
            b'x-proxy-py-version',
            bytes_(__version__),
        )
        return request
