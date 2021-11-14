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

from ..common.utils import bytes_
from ..http.parser import HttpParser, httpMethods
from ..http.proxy import HttpProxyBasePlugin


class ModifyPostDataPlugin(HttpProxyBasePlugin):
    """Modify POST request body before sending to upstream server."""

    MODIFIED_BODY = b'{"key": "modified"}'

    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        return request

    def handle_client_request(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        if request.method == httpMethods.POST:
            request.body = ModifyPostDataPlugin.MODIFIED_BODY
            # Update Content-Length header only when request is NOT chunked
            # encoded
            if not request.is_chunked_encoded():
                request.add_header(
                    b'Content-Length',
                    bytes_(len(request.body)),
                )
            # Enforce content-type json
            if request.has_header(b'Content-Type'):
                request.del_header(b'Content-Type')
            request.add_header(b'Content-Type', b'application/json')
        return request
