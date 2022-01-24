# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import logging
from typing import List, Tuple

from proxy.http.parser import HttpParser
from proxy.http.server import HttpWebServerBasePlugin, httpProtocolTypes
from proxy.http.responses import okResponse


logger = logging.getLogger(__name__)


class MyWebServerPlugin(HttpWebServerBasePlugin):
    """Demonstrates inbuilt web server routing using plugin."""

    def routes(self) -> List[Tuple[int, str]]:
        return [
            (httpProtocolTypes.HTTP, r'/$'),
        ]

    def handle_request(self, request: HttpParser) -> None:
        self.client.queue(okResponse(content=b'Hello World'))
