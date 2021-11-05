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
from urllib import parse as urlparse

from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin


class RedirectToCustomServerPlugin(HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = b'http://localhost:8899/'

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        # Redirect all non-https requests to inbuilt WebServer.
        if not request.is_https_tunnel():
            request.set_url(self.UPSTREAM_SERVER)
            # Update Host header too, otherwise upstream can reject our request
            if request.has_header(b'Host'):
                request.del_header(b'Host')
            request.add_header(
                b'Host', urlparse.urlsplit(
                    self.UPSTREAM_SERVER,
                ).netloc,
            )
        return request
