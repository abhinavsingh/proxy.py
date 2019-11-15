# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Programmable, TLS interception capable
    proxy server for Application debugging, testing and development.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
from typing import Optional

from ..common.utils import bytes_
from ..http.parser import HttpParser
from ..http.proxy import HttpProxyBasePlugin
from ..http.methods import httpMethods


class ModifyPostDataPlugin(HttpProxyBasePlugin):
    """Modify POST request body before sending to upstream server."""

    MODIFIED_BODY = b'{"key": "modified"}'

    def before_upstream_connection(
            self, request: HttpParser) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser) -> Optional[HttpParser]:
        if request.method == httpMethods.POST:
            request.body = ModifyPostDataPlugin.MODIFIED_BODY
            # Update Content-Length header only when request is NOT chunked
            # encoded
            if not request.is_chunked_encoded():
                request.add_header(b'Content-Length',
                                   bytes_(len(request.body)))
            # Enforce content-type json
            if request.has_header(b'Content-Type'):
                request.del_header(b'Content-Type')
            request.add_header(b'Content-Type', b'application/json')
        return request

    def handle_upstream_chunk(self, chunk: bytes) -> bytes:
        return chunk

    def on_upstream_connection_close(self) -> None:
        pass
