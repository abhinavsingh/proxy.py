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

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        """NOTE: Modification of client request under TLS interception WILL NOT WORK
        through before_upstream_connection hook override.  This example plugin is demonstrate
        how to modify headers for all scenarios (with or without interception).
        """
        request.add_header(
            b'x-proxy-py-version',
            bytes_(__version__),
        )
        return request
