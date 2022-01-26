# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import os
import logging
from typing import List, Tuple

from ..http.parser import HttpParser
from ..http.server import HttpWebServerBasePlugin, httpProtocolTypes
from ..http.responses import permanentRedirectResponse


logger = logging.getLogger(__name__)


class ProxyDashboard(HttpWebServerBasePlugin):
    """Proxy Dashboard."""

    # Redirects to /dashboard/
    REDIRECT_ROUTES = [
        (httpProtocolTypes.HTTP, r'/dashboard$'),
        (httpProtocolTypes.HTTPS, r'/dashboard$'),
        (httpProtocolTypes.HTTP, r'/dashboard/proxy.html$'),
        (httpProtocolTypes.HTTPS, r'/dashboard/proxy.html$'),
    ]

    # Index html route
    INDEX_ROUTES = [
        (httpProtocolTypes.HTTP, r'/dashboard/$'),
        (httpProtocolTypes.HTTPS, r'/dashboard/$'),
    ]

    def routes(self) -> List[Tuple[int, str]]:
        return ProxyDashboard.REDIRECT_ROUTES + \
            ProxyDashboard.INDEX_ROUTES

    def handle_request(self, request: HttpParser) -> None:
        if request.path == b'/dashboard/':
            self.client.queue(
                self.serve_static_file(
                    os.path.join(
                        self.flags.static_server_dir,
                        'dashboard', 'proxy.html',
                    ),
                    self.flags.min_compression_length,
                ),
            )
        elif request.path in (
                b'/dashboard',
                b'/dashboard/proxy.html',
        ):
            self.client.queue(permanentRedirectResponse(b'/dashboard/'))
