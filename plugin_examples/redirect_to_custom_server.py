# -*- coding: utf-8 -*-
"""
    py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable Proxy Server in a single Python file.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from urllib import parse as urlparse
from typing import Optional

from proxy.http_proxy import HttpProxyBasePlugin
from proxy.http_parser import HttpParser
from proxy.http_methods import httpMethods


class RedirectToCustomServerPlugin(HttpProxyBasePlugin):
    """Modifies client request to redirect all incoming requests to a fixed server address."""

    UPSTREAM_SERVER = b'http://localhost:8899/'

    def before_upstream_connection(self, request: HttpParser) -> Optional[HttpParser]:
        # Redirect all non-https requests to inbuilt WebServer.
        if request.method != httpMethods.CONNECT:
            request.set_url(self.UPSTREAM_SERVER)
            # Update Host header too, otherwise upstream can reject our request
            if request.has_header(b'Host'):
                request.del_header(b'Host')
            request.add_header(b'Host', urlparse.urlsplit(self.UPSTREAM_SERVER).netloc)
        return request

    def handle_client_request(self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
